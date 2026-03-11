#!/usr/bin/env python3
"""
Evidence Collection System for BugHound

Automatically captures and organizes evidence for security findings:
- Screenshots of web services and vulnerabilities
- HTTP request/response pairs
- Payloads and proof-of-concepts
- Error messages and response content
"""

import asyncio
import json
import logging
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import base64
import subprocess

logger = logging.getLogger(__name__)


class EvidenceType(Enum):
    """Types of evidence that can be collected"""
    SCREENSHOT = "screenshot"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    PAYLOAD = "payload"
    ERROR_MESSAGE = "error_message"
    PROOF_OF_CONCEPT = "proof_of_concept"
    NETWORK_TRAFFIC = "network_traffic"
    FILE_CONTENT = "file_content"


@dataclass
class Evidence:
    """Represents a piece of evidence for a security finding"""
    evidence_id: str
    evidence_type: EvidenceType
    finding_id: str
    target_url: str
    title: str
    description: str
    file_path: Optional[str] = None
    content: Optional[str] = None
    metadata: Dict[str, Any] = None
    timestamp: str = None
    size_bytes: int = 0
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class HttpEvidence:
    """Specialized evidence for HTTP requests/responses"""
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = None
    response_body: Optional[str] = None
    response_time_ms: int = 0
    
    def __post_init__(self):
        if self.response_headers is None:
            self.response_headers = {}


class EvidenceCollector:
    """Automated evidence collection for security findings"""
    
    def __init__(self, workspace_manager):
        """
        Initialize evidence collector
        
        Args:
            workspace_manager: WorkspaceManager instance for file operations
        """
        self.workspace_manager = workspace_manager
        self.evidence_cache = {}  # Cache evidence to avoid duplicates
        
    async def collect_evidence_for_finding(
        self, 
        workspace_id: str,
        finding_data: Dict[str, Any],
        target_url: str,
        vulnerability_type: str = "unknown"
    ) -> List[Evidence]:
        """
        Collect comprehensive evidence for a security finding
        
        Args:
            workspace_id: Workspace to store evidence in
            finding_data: Vulnerability or finding data
            target_url: Target URL or service
            vulnerability_type: Type of vulnerability found
            
        Returns:
            List of collected evidence items
        """
        
        evidence_items = []
        
        try:
            logger.info(f"Collecting evidence for finding on {target_url}")
            
            # Generate unique finding ID
            finding_id = self._generate_finding_id(finding_data, target_url)
            
            # Collect screenshot evidence
            screenshot_evidence = await self._collect_screenshot_evidence(
                workspace_id, finding_id, target_url, finding_data
            )
            if screenshot_evidence:
                evidence_items.append(screenshot_evidence)
            
            # Collect HTTP evidence if available
            http_evidence = await self._collect_http_evidence(
                workspace_id, finding_id, target_url, finding_data
            )
            if http_evidence:
                evidence_items.extend(http_evidence)
            
            # Collect payload evidence
            payload_evidence = await self._collect_payload_evidence(
                workspace_id, finding_id, target_url, finding_data
            )
            if payload_evidence:
                evidence_items.append(payload_evidence)
            
            # Collect proof-of-concept evidence
            poc_evidence = await self._collect_poc_evidence(
                workspace_id, finding_id, target_url, finding_data, vulnerability_type
            )
            if poc_evidence:
                evidence_items.append(poc_evidence)
            
            # Save evidence index
            await self._save_evidence_index(workspace_id, finding_id, evidence_items)
            
            logger.info(f"Collected {len(evidence_items)} evidence items for finding {finding_id}")
            return evidence_items
            
        except Exception as e:
            logger.error(f"Error collecting evidence: {e}")
            return []
    
    async def collect_live_host_evidence(
        self, 
        workspace_id: str, 
        live_hosts: List[Dict[str, Any]]
    ) -> Dict[str, List[Evidence]]:
        """
        Collect evidence for all discovered live hosts
        
        Args:
            workspace_id: Workspace to store evidence in
            live_hosts: List of live host data from httpx/other tools
            
        Returns:
            Dictionary mapping URLs to evidence lists
        """
        
        evidence_by_host = {}
        
        try:
            logger.info(f"Collecting evidence for {len(live_hosts)} live hosts")
            
            for host_data in live_hosts:
                url = host_data.get('url', '')
                if not url:
                    continue
                
                finding_id = self._generate_finding_id(host_data, url)
                evidence_items = []
                
                # Take screenshot of the live service
                screenshot_evidence = await self._collect_screenshot_evidence(
                    workspace_id, finding_id, url, host_data, evidence_title="Live Service Screenshot"
                )
                if screenshot_evidence:
                    evidence_items.append(screenshot_evidence)
                
                # Collect HTTP response evidence
                http_evidence = await self._collect_http_response_evidence(
                    workspace_id, finding_id, url, host_data
                )
                if http_evidence:
                    evidence_items.extend(http_evidence)
                
                evidence_by_host[url] = evidence_items
                
                # Save evidence index for this host
                await self._save_evidence_index(workspace_id, finding_id, evidence_items)
            
            logger.info(f"Collected evidence for {len(evidence_by_host)} hosts")
            return evidence_by_host
            
        except Exception as e:
            logger.error(f"Error collecting live host evidence: {e}")
            return {}
    
    async def _collect_screenshot_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        finding_data: Dict[str, Any],
        evidence_title: str = "Vulnerability Screenshot"
    ) -> Optional[Evidence]:
        """Collect screenshot evidence for a URL"""
        
        try:
            # Import screenshot tool
            from ..tools.utils.screenshot_tool import ScreenshotTool
            
            screenshot_tool = ScreenshotTool()
            
            # Take screenshot
            screenshot_result = await screenshot_tool.capture_url(
                url=url,
                workspace_id=workspace_id,
                finding_id=finding_id,
                context=finding_data
            )
            
            if screenshot_result.get('success'):
                file_path = screenshot_result.get('file_path')
                file_size = screenshot_result.get('file_size', 0)
                
                evidence = Evidence(
                    evidence_id=f"{finding_id}_screenshot",
                    evidence_type=EvidenceType.SCREENSHOT,
                    finding_id=finding_id,
                    target_url=url,
                    title=evidence_title,
                    description=f"Screenshot of {url} showing vulnerability or service state",
                    file_path=file_path,
                    size_bytes=file_size,
                    metadata={
                        'screenshot_method': screenshot_result.get('method', 'unknown'),
                        'viewport_size': screenshot_result.get('viewport_size'),
                        'page_title': screenshot_result.get('page_title'),
                        'final_url': screenshot_result.get('final_url', url)
                    }
                )
                
                return evidence
                
        except ImportError:
            logger.warning("Screenshot tool not available - skipping screenshot evidence")
        except Exception as e:
            logger.error(f"Error collecting screenshot evidence: {e}")
        
        return None
    
    async def _collect_http_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        finding_data: Dict[str, Any]
    ) -> List[Evidence]:
        """Collect HTTP request/response evidence"""
        
        evidence_items = []
        
        try:
            # Extract HTTP data from finding_data if available
            curl_command = finding_data.get('curl_command', '')
            
            if curl_command:
                # Parse curl command to extract request details
                request_evidence = await self._parse_curl_command(
                    workspace_id, finding_id, url, curl_command
                )
                if request_evidence:
                    evidence_items.append(request_evidence)
            
            # If this is nuclei data, extract template information
            template_info = finding_data.get('info', {})
            if template_info:
                template_evidence = await self._collect_template_evidence(
                    workspace_id, finding_id, url, template_info
                )
                if template_evidence:
                    evidence_items.append(template_evidence)
            
            return evidence_items
            
        except Exception as e:
            logger.error(f"Error collecting HTTP evidence: {e}")
            return []
    
    async def _collect_http_response_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        host_data: Dict[str, Any]
    ) -> List[Evidence]:
        """Collect HTTP response evidence from host data"""
        
        evidence_items = []
        
        try:
            # Create HTTP response evidence
            response_data = {
                'status_code': host_data.get('status_code'),
                'title': host_data.get('title'),
                'server': host_data.get('server'),
                'content_length': host_data.get('content_length'),
                'technologies': host_data.get('technologies', [])
            }
            
            evidence = Evidence(
                evidence_id=f"{finding_id}_http_response",
                evidence_type=EvidenceType.HTTP_RESPONSE,
                finding_id=finding_id,
                target_url=url,
                title="HTTP Response Analysis",
                description=f"HTTP response analysis for {url}",
                content=json.dumps(response_data, indent=2),
                metadata={
                    'response_analysis': response_data,
                    'collection_method': 'httpx',
                    'response_time': host_data.get('response_time'),
                    'final_url': host_data.get('final_url', url)
                }
            )
            
            evidence_items.append(evidence)
            
            # Save HTTP response to file
            await self._save_evidence_to_file(workspace_id, evidence)
            
            return evidence_items
            
        except Exception as e:
            logger.error(f"Error collecting HTTP response evidence: {e}")
            return []
    
    async def _collect_payload_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        finding_data: Dict[str, Any]
    ) -> Optional[Evidence]:
        """Collect payload evidence from vulnerability data"""
        
        try:
            # Extract payload information
            payloads = []
            
            # Check for nuclei template payloads
            template_id = finding_data.get('template_id', '')
            if template_id:
                payloads.append(f"Template: {template_id}")
            
            # Extract curl command payloads
            curl_command = finding_data.get('curl_command', '')
            if curl_command:
                payloads.append(f"Curl: {curl_command}")
            
            # Look for other payload indicators
            matched_at = finding_data.get('matched_at', '')
            if matched_at and matched_at != url:
                payloads.append(f"Matched URL: {matched_at}")
            
            if payloads:
                payload_content = "\n".join(payloads)
                
                evidence = Evidence(
                    evidence_id=f"{finding_id}_payload",
                    evidence_type=EvidenceType.PAYLOAD,
                    finding_id=finding_id,
                    target_url=url,
                    title="Attack Payloads",
                    description="Payloads and methods used to identify the vulnerability",
                    content=payload_content,
                    metadata={
                        'payload_count': len(payloads),
                        'template_id': template_id,
                        'detection_method': finding_data.get('type', 'unknown')
                    }
                )
                
                # Save payload evidence to file
                await self._save_evidence_to_file(workspace_id, evidence)
                
                return evidence
                
        except Exception as e:
            logger.error(f"Error collecting payload evidence: {e}")
        
        return None
    
    async def _collect_poc_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        finding_data: Dict[str, Any],
        vulnerability_type: str
    ) -> Optional[Evidence]:
        """Generate and collect proof-of-concept evidence"""
        
        try:
            # Generate PoC based on vulnerability type and finding data
            poc_content = await self._generate_proof_of_concept(
                url, finding_data, vulnerability_type
            )
            
            if poc_content:
                evidence = Evidence(
                    evidence_id=f"{finding_id}_poc",
                    evidence_type=EvidenceType.PROOF_OF_CONCEPT,
                    finding_id=finding_id,
                    target_url=url,
                    title="Proof of Concept",
                    description=f"Proof-of-concept demonstration for {vulnerability_type} vulnerability",
                    content=poc_content,
                    metadata={
                        'vulnerability_type': vulnerability_type,
                        'template_id': finding_data.get('template_id'),
                        'severity': finding_data.get('info', {}).get('severity', 'unknown'),
                        'poc_type': 'automated_generation'
                    }
                )
                
                # Save PoC evidence to file
                await self._save_evidence_to_file(workspace_id, evidence)
                
                return evidence
                
        except Exception as e:
            logger.error(f"Error collecting PoC evidence: {e}")
        
        return None
    
    async def _parse_curl_command(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        curl_command: str
    ) -> Optional[Evidence]:
        """Parse curl command and create HTTP request evidence"""
        
        try:
            # Basic curl command parsing
            method = "GET"
            headers = {}
            data = None
            
            # Extract method
            if "-X POST" in curl_command or "--request POST" in curl_command:
                method = "POST"
            elif "-X PUT" in curl_command:
                method = "PUT"
            elif "-X DELETE" in curl_command:
                method = "DELETE"
            
            # Extract headers (simplified parsing)
            header_matches = re.findall(r"-H ['\"]([^'\"]+)['\"]", curl_command)
            for header in header_matches:
                if ":" in header:
                    key, value = header.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            # Extract data
            data_matches = re.findall(r"-d ['\"]([^'\"]+)['\"]", curl_command)
            if data_matches:
                data = data_matches[0]
            
            # Create HTTP request evidence
            request_content = {
                'method': method,
                'url': url,
                'headers': headers,
                'data': data,
                'curl_command': curl_command
            }
            
            evidence = Evidence(
                evidence_id=f"{finding_id}_http_request",
                evidence_type=EvidenceType.HTTP_REQUEST,
                finding_id=finding_id,
                target_url=url,
                title="HTTP Request Details",
                description="Complete HTTP request used to identify the vulnerability",
                content=json.dumps(request_content, indent=2),
                metadata={
                    'request_method': method,
                    'header_count': len(headers),
                    'has_payload': data is not None,
                    'curl_complexity': len(curl_command.split())
                }
            )
            
            # Save request evidence to file
            await self._save_evidence_to_file(workspace_id, evidence)
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error parsing curl command: {e}")
            return None
    
    async def _collect_template_evidence(
        self, 
        workspace_id: str, 
        finding_id: str, 
        url: str, 
        template_info: Dict[str, Any]
    ) -> Optional[Evidence]:
        """Collect nuclei template information as evidence"""
        
        try:
            template_content = {
                'name': template_info.get('name'),
                'severity': template_info.get('severity'),
                'description': template_info.get('description'),
                'tags': template_info.get('tags', []),
                'author': template_info.get('author'),
                'reference': template_info.get('reference', [])
            }
            
            evidence = Evidence(
                evidence_id=f"{finding_id}_template",
                evidence_type=EvidenceType.FILE_CONTENT,
                finding_id=finding_id,
                target_url=url,
                title="Detection Template Information",
                description="Nuclei template details used for vulnerability detection",
                content=json.dumps(template_content, indent=2),
                metadata={
                    'template_source': 'nuclei',
                    'severity': template_info.get('severity'),
                    'tag_count': len(template_info.get('tags', [])),
                    'has_references': bool(template_info.get('reference'))
                }
            )
            
            # Save template evidence to file
            await self._save_evidence_to_file(workspace_id, evidence)
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting template evidence: {e}")
            return None
    
    async def _generate_proof_of_concept(
        self, 
        url: str, 
        finding_data: Dict[str, Any], 
        vulnerability_type: str
    ) -> Optional[str]:
        """Generate proof-of-concept code for the vulnerability"""
        
        try:
            template_id = finding_data.get('template_id', '')
            curl_command = finding_data.get('curl_command', '')
            severity = finding_data.get('info', {}).get('severity', 'unknown')
            
            poc_lines = [
                f"# Proof of Concept for {vulnerability_type}",
                f"# Target: {url}",
                f"# Severity: {severity.upper()}",
                f"# Template: {template_id}",
                "",
                "## Reproduction Steps:",
                "",
            ]
            
            if curl_command:
                poc_lines.extend([
                    "### Using curl:",
                    "```bash",
                    curl_command,
                    "```",
                    ""
                ])
            
            # Add manual verification steps
            poc_lines.extend([
                "### Manual Verification:",
                f"1. Navigate to: {url}",
                "2. Observe the response for vulnerability indicators",
                "3. Check for the specific conditions that trigger this finding",
                ""
            ])
            
            # Add impact explanation
            poc_lines.extend([
                "### Impact:",
                "This vulnerability could potentially allow an attacker to:",
                "- Access sensitive information",
                "- Modify application behavior", 
                "- Escalate privileges (depending on context)",
                "",
                "### Remediation:",
                "1. Review the affected endpoint/service",
                "2. Apply security patches if available",
                "3. Implement proper input validation/sanitization",
                "4. Configure security headers appropriately",
                ""
            ])
            
            return "\n".join(poc_lines)
            
        except Exception as e:
            logger.error(f"Error generating PoC: {e}")
            return None
    
    async def _save_evidence_to_file(self, workspace_id: str, evidence: Evidence) -> bool:
        """Save evidence content to a file in the workspace"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return False
            
            # Create evidence directory structure
            evidence_dir = workspace.workspace_path / "reports" / "evidence"
            evidence_type_dir = evidence_dir / evidence.evidence_type.value
            evidence_type_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_url = re.sub(r'[^\w\-_.]', '_', evidence.target_url.replace('https://', '').replace('http://', ''))
            
            # Choose file extension based on evidence type
            extensions = {
                EvidenceType.HTTP_REQUEST: '.json',
                EvidenceType.HTTP_RESPONSE: '.json',
                EvidenceType.PAYLOAD: '.txt',
                EvidenceType.PROOF_OF_CONCEPT: '.md',
                EvidenceType.FILE_CONTENT: '.json',
                EvidenceType.ERROR_MESSAGE: '.txt'
            }
            
            ext = extensions.get(evidence.evidence_type, '.txt')
            filename = f"{clean_url}_{evidence.evidence_type.value}_{timestamp}{ext}"
            file_path = evidence_type_dir / filename
            
            # Save content to file
            if evidence.content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(evidence.content)
                
                # Update evidence with file path
                evidence.file_path = str(file_path)
                evidence.size_bytes = file_path.stat().st_size
                
                logger.debug(f"Saved evidence to: {file_path}")
                return True
                
        except Exception as e:
            logger.error(f"Error saving evidence to file: {e}")
        
        return False
    
    async def _save_evidence_index(
        self, 
        workspace_id: str, 
        finding_id: str, 
        evidence_items: List[Evidence]
    ) -> bool:
        """Save evidence index for a finding"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return False
            
            # Create evidence directory
            evidence_dir = workspace.workspace_path / "reports" / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            # Create index entry
            index_data = {
                'finding_id': finding_id,
                'evidence_count': len(evidence_items),
                'collected_at': datetime.now().isoformat(),
                'evidence_items': []
            }
            
            for evidence in evidence_items:
                index_data['evidence_items'].append({
                    'evidence_id': evidence.evidence_id,
                    'evidence_type': evidence.evidence_type.value,
                    'title': evidence.title,
                    'description': evidence.description,
                    'file_path': evidence.file_path,
                    'size_bytes': evidence.size_bytes,
                    'target_url': evidence.target_url,
                    'timestamp': evidence.timestamp,
                    'metadata': evidence.metadata
                })
            
            # Save index file
            index_file = evidence_dir / f"{finding_id}_index.json"
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Saved evidence index: {index_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving evidence index: {e}")
            return False
    
    def _generate_finding_id(self, finding_data: Dict[str, Any], target_url: str) -> str:
        """Generate a unique finding ID"""
        
        # Create a hash based on finding data and URL
        content = f"{target_url}_{finding_data.get('template_id', '')}_{finding_data.get('type', '')}"
        finding_hash = hashlib.md5(content.encode()).hexdigest()[:8]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"finding_{timestamp}_{finding_hash}"
    
    async def list_evidence_for_workspace(self, workspace_id: str) -> Dict[str, Any]:
        """List all evidence collected for a workspace"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return {}
            
            evidence_dir = workspace.workspace_path / "reports" / "evidence"
            if not evidence_dir.exists():
                return {'evidence_count': 0, 'findings': []}
            
            # Find all index files
            index_files = list(evidence_dir.glob("*_index.json"))
            findings = []
            total_evidence = 0
            
            for index_file in index_files:
                try:
                    with open(index_file, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)
                    
                    findings.append(index_data)
                    total_evidence += index_data.get('evidence_count', 0)
                    
                except Exception as e:
                    logger.warning(f"Error reading evidence index {index_file}: {e}")
            
            return {
                'evidence_count': total_evidence,
                'finding_count': len(findings),
                'findings': findings,
                'evidence_directory': str(evidence_dir)
            }
            
        except Exception as e:
            logger.error(f"Error listing evidence: {e}")
            return {}
    
    async def get_evidence_for_finding(self, workspace_id: str, finding_id: str) -> List[Evidence]:
        """Get all evidence for a specific finding"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return []
            
            evidence_dir = workspace.workspace_path / "reports" / "evidence"
            index_file = evidence_dir / f"{finding_id}_index.json"
            
            if not index_file.exists():
                return []
            
            # Load evidence index
            with open(index_file, 'r', encoding='utf-8') as f:
                index_data = json.load(f)
            
            # Reconstruct evidence objects
            evidence_items = []
            for item_data in index_data.get('evidence_items', []):
                evidence = Evidence(
                    evidence_id=item_data['evidence_id'],
                    evidence_type=EvidenceType(item_data['evidence_type']),
                    finding_id=item_data.get('finding_id', finding_id),
                    target_url=item_data['target_url'],
                    title=item_data['title'],
                    description=item_data['description'],
                    file_path=item_data.get('file_path'),
                    size_bytes=item_data.get('size_bytes', 0),
                    metadata=item_data.get('metadata', {}),
                    timestamp=item_data.get('timestamp')
                )
                
                # Load content if file exists
                if evidence.file_path and Path(evidence.file_path).exists():
                    try:
                        with open(evidence.file_path, 'r', encoding='utf-8') as f:
                            evidence.content = f.read()
                    except Exception as e:
                        logger.warning(f"Could not load evidence content from {evidence.file_path}: {e}")
                
                evidence_items.append(evidence)
            
            return evidence_items
            
        except Exception as e:
            logger.error(f"Error getting evidence for finding {finding_id}: {e}")
            return []