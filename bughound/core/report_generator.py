#!/usr/bin/env python3
"""
Professional Report Generation System for BugHound

Generates multiple types of security reports from reconnaissance data:
- Executive Summary (non-technical, business-focused)
- Technical Report (detailed findings with evidence)
- Bug Bounty Submission (platform-ready format)
- Change Report (what's new since last scan)
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types of reports that can be generated"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_REPORT = "technical_report"
    BUG_BOUNTY_SUBMISSION = "bug_bounty_submission"
    CHANGE_REPORT = "change_report"


class ReportFormat(Enum):
    """Output formats for reports"""
    HTML = "html"
    MARKDOWN = "md"
    PDF = "pdf"
    JSON = "json"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding for reporting"""
    title: str
    severity: SeverityLevel
    description: str
    impact: str
    affected_url: str
    evidence: Dict[str, Any]
    recommendation: str
    cve_references: List[str] = None
    cvss_score: float = None
    discovery_method: str = ""
    proof_of_concept: str = ""
    
    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []


@dataclass
class ScanStatistics:
    """Statistics about a reconnaissance scan"""
    target: str
    scan_date: str
    workspace_id: str
    duration_minutes: int
    tools_used: List[str]
    subdomains_found: int
    live_hosts: int
    open_ports: int
    vulnerabilities_found: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    critical_severity_count: int


@dataclass
class ReportData:
    """Complete data for report generation"""
    statistics: ScanStatistics
    findings: List[Finding]
    ai_insights: Optional[Dict[str, Any]] = None
    change_data: Optional[Dict[str, Any]] = None
    recommendations: List[str] = None
    executive_summary: str = ""
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class ReportGenerator:
    """Professional report generator for security reconnaissance data"""
    
    def __init__(self, workspace_manager, ai_client=None):
        """
        Initialize report generator
        
        Args:
            workspace_manager: WorkspaceManager instance for data access
            ai_client: Optional AI client for enhanced report generation
        """
        self.workspace_manager = workspace_manager
        self.ai_client = ai_client
        
        # Risk scoring and severity mapping
        self.severity_scores = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 7,
            SeverityLevel.MEDIUM: 4,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        # Platform-specific formatting
        self.platform_configs = {
            "hackerone": {
                "title_format": "## {title}",
                "severity_field": "**Severity:** {severity}",
                "impact_section": "## Impact\n{impact}",
                "poc_section": "## Proof of Concept\n{poc}",
                "recommendation_section": "## Recommendation\n{recommendation}"
            },
            "bugcrowd": {
                "title_format": "# {title}",
                "severity_field": "**Risk:** {severity}",
                "impact_section": "## Business Impact\n{impact}",
                "poc_section": "## Steps to Reproduce\n{poc}",
                "recommendation_section": "## Remediation\n{recommendation}"
            }
        }
    
    async def generate_report(
        self, 
        workspace_id: str, 
        report_type: ReportType,
        format: ReportFormat = ReportFormat.MARKDOWN,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive report from workspace data
        
        Args:
            workspace_id: ID of workspace to generate report from
            report_type: Type of report to generate
            format: Output format for the report
            options: Additional options for report generation
            
        Returns:
            Dictionary containing report content and metadata
        """
        
        options = options or {}
        
        try:
            logger.info(f"Generating {report_type.value} report for workspace {workspace_id}")
            
            # Extract and prepare data
            report_data = await self._prepare_report_data(workspace_id, options)
            if not report_data:
                raise ValueError("Failed to prepare report data")
            
            # Generate report based on type
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                content = await self._generate_executive_summary(report_data, format, options)
            elif report_type == ReportType.TECHNICAL_REPORT:
                content = await self._generate_technical_report(report_data, format, options)
            elif report_type == ReportType.BUG_BOUNTY_SUBMISSION:
                content = await self._generate_bug_bounty_report(report_data, format, options)
            elif report_type == ReportType.CHANGE_REPORT:
                content = await self._generate_change_report(report_data, format, options)
            else:
                raise ValueError(f"Unsupported report type: {report_type}")
            
            # Create report metadata
            metadata = {
                "report_type": report_type.value,
                "format": format.value,
                "workspace_id": workspace_id,
                "target": report_data.statistics.target,
                "generated_date": datetime.now().isoformat(),
                "total_findings": len(report_data.findings),
                "critical_findings": len([f for f in report_data.findings if f.severity == SeverityLevel.CRITICAL]),
                "high_findings": len([f for f in report_data.findings if f.severity == SeverityLevel.HIGH]),
                "generator_version": "1.0.0"
            }
            
            # Save report to file
            file_path = await self.save_report(workspace_id, content, metadata)
            
            logger.info(f"Report generation completed: {len(content)} characters, saved to {file_path}")
            
            return {
                "content": content,
                "metadata": metadata,
                "file_path": file_path,
                "file_size": len(content.encode('utf-8')),
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {
                "content": "",
                "metadata": {},
                "success": False,
                "error": str(e)
            }
    
    async def _prepare_report_data(self, workspace_id: str, options: Dict[str, Any]) -> Optional[ReportData]:
        """Prepare comprehensive data for report generation"""
        
        try:
            # Get workspace data
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                logger.error(f"Workspace {workspace_id} not found")
                return None
            
            # Get all results
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            if not all_results:
                logger.error(f"No results found for workspace {workspace_id}")
                return None
            
            # Extract statistics
            statistics = self._extract_statistics(workspace, all_results)
            
            # Extract and classify findings
            findings = await self._extract_findings(all_results, workspace.metadata.target)
            
            # Get AI insights if available
            ai_insights = None
            if self.ai_client and self.ai_client.is_available():
                ai_insights = await self._generate_ai_insights(statistics, findings)
            
            # Get change data if requested
            change_data = None
            if options.get("include_changes"):
                change_data = await self._get_change_data(workspace_id)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(statistics, findings, ai_insights)
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary_text(statistics, findings, ai_insights)
            
            return ReportData(
                statistics=statistics,
                findings=findings,
                ai_insights=ai_insights,
                change_data=change_data,
                recommendations=recommendations,
                executive_summary=executive_summary
            )
            
        except Exception as e:
            logger.error(f"Error preparing report data: {e}")
            return None
    
    def _extract_statistics(self, workspace, all_results) -> ScanStatistics:
        """Extract scan statistics from workspace data"""
        
        summary_stats = all_results.get('summary_stats', {})
        tools = list(all_results.get('tools', {}).keys())
        
        # Calculate scan duration (approximation)
        duration_minutes = len(tools) * 2  # Rough estimate: 2 minutes per tool
        
        # Count vulnerabilities by severity
        vulnerabilities = []
        if 'nuclei' in all_results.get('tools', {}):
            nuclei_data = all_results['tools']['nuclei']
            vulns = nuclei_data.get('results', {}).get('vulnerabilities', [])
            vulnerabilities.extend(vulns)
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return ScanStatistics(
            target=workspace.metadata.target,
            scan_date=workspace.metadata.created_date,
            workspace_id=workspace.metadata.workspace_id,
            duration_minutes=duration_minutes,
            tools_used=tools,
            subdomains_found=summary_stats.get('total_subdomains_found', 0),
            live_hosts=summary_stats.get('total_live_hosts', 0),
            open_ports=summary_stats.get('total_open_ports', 0),
            vulnerabilities_found=len(vulnerabilities),
            critical_severity_count=severity_counts['critical'],
            high_severity_count=severity_counts['high'],
            medium_severity_count=severity_counts['medium'],
            low_severity_count=severity_counts['low']
        )
    
    async def _extract_findings(self, all_results: Dict[str, Any], target: str) -> List[Finding]:
        """Extract and format security findings from scan results"""
        
        findings = []
        
        try:
            # Extract vulnerability findings from nuclei
            if 'nuclei' in all_results.get('tools', {}):
                nuclei_data = all_results['tools']['nuclei']
                vulns = nuclei_data.get('results', {}).get('vulnerabilities', [])
                
                for vuln in vulns:
                    finding = self._create_vulnerability_finding(vuln, target)
                    if finding:
                        findings.append(finding)
            
            # Extract service findings from nmap
            if 'nmap' in all_results.get('tools', {}):
                nmap_data = all_results['tools']['nmap']
                services = nmap_data.get('results', {}).get('services', [])
                
                for service in services:
                    finding = self._create_service_finding(service, target)
                    if finding:
                        findings.append(finding)
            
            # Extract subdomain takeover opportunities
            subdomain_findings = self._analyze_subdomain_risks(all_results, target)
            findings.extend(subdomain_findings)
            
            # Sort findings by severity (critical first)
            findings.sort(key=lambda f: self.severity_scores[f.severity], reverse=True)
            
            logger.info(f"Extracted {len(findings)} security findings")
            return findings
            
        except Exception as e:
            logger.error(f"Error extracting findings: {e}")
            return []
    
    def _create_vulnerability_finding(self, vuln: Dict[str, Any], target: str) -> Optional[Finding]:
        """Create a Finding object from nuclei vulnerability data"""
        
        try:
            # Map nuclei severity to our enum
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW,
                'info': SeverityLevel.INFO
            }
            
            severity = severity_map.get(vuln.get('severity', 'low').lower(), SeverityLevel.LOW)
            
            # Build affected URL
            affected_url = vuln.get('matched_at', f"https://{target}")
            
            # Extract CVE references
            cve_refs = []
            template_id = vuln.get('template_id', '')
            if 'cve-' in template_id.lower():
                cve_refs.append(template_id.upper())
            
            # Generate impact description
            impact = self._generate_impact_description(vuln, severity)
            
            # Generate recommendation
            recommendation = self._generate_vulnerability_recommendation(vuln, severity)
            
            return Finding(
                title=vuln.get('template_name', 'Security Vulnerability'),
                severity=severity,
                description=vuln.get('description', f"Vulnerability detected by template {template_id}"),
                impact=impact,
                affected_url=affected_url,
                evidence={
                    'template_id': template_id,
                    'matcher_name': vuln.get('matcher_name', ''),
                    'matched_at': affected_url,
                    'curl_command': vuln.get('curl_command', ''),
                    'request': vuln.get('request', ''),
                    'response': vuln.get('response', '')
                },
                recommendation=recommendation,
                cve_references=cve_refs,
                discovery_method="Nuclei Template Scanning",
                proof_of_concept=self._generate_poc_for_vulnerability(vuln)
            )
            
        except Exception as e:
            logger.error(f"Error creating vulnerability finding: {e}")
            return None
    
    def _create_service_finding(self, service: Dict[str, Any], target: str) -> Optional[Finding]:
        """Create a Finding object from nmap service data"""
        
        try:
            host = service.get('host', target)
            port = service.get('port', 0)
            service_name = service.get('name', 'unknown')
            version = service.get('version', '')
            
            # Determine severity based on service type and version
            severity = self._assess_service_severity(service_name, version, port)
            
            # Skip info-level findings for common services
            if severity == SeverityLevel.INFO and port in [80, 443, 22]:
                return None
            
            title = f"Exposed {service_name.title()} Service"
            if version:
                title += f" ({version})"
            
            description = f"Service {service_name} detected on port {port}"
            if version:
                description += f" with version {version}"
            
            impact = self._generate_service_impact(service_name, port, version)
            recommendation = self._generate_service_recommendation(service_name, port)
            
            return Finding(
                title=title,
                severity=severity,
                description=description,
                impact=impact,
                affected_url=f"{host}:{port}",
                evidence={
                    'host': host,
                    'port': port,
                    'service': service_name,
                    'version': version,
                    'state': service.get('state', 'open'),
                    'banner': service.get('banner', '')
                },
                recommendation=recommendation,
                discovery_method="Nmap Port Scanning",
                proof_of_concept=f"nmap -sV -p {port} {host}"
            )
            
        except Exception as e:
            logger.error(f"Error creating service finding: {e}")
            return None
    
    def _analyze_subdomain_risks(self, all_results: Dict[str, Any], target: str) -> List[Finding]:
        """Analyze subdomains for potential security risks"""
        
        findings = []
        
        try:
            # Get subdomain data
            subdomains = []
            if 'subfinder' in all_results.get('tools', {}):
                subfinder_data = all_results['tools']['subfinder']
                subdomains.extend(subfinder_data.get('results', {}).get('subdomains', []))
            
            # Get live host data
            live_hosts = []
            if 'httpx' in all_results.get('tools', {}):
                httpx_data = all_results['tools']['httpx']
                live_hosts.extend(httpx_data.get('results', {}).get('live_hosts', []))
            
            live_host_names = {host.get('host', '') for host in live_hosts}
            
            # Check for subdomain takeover opportunities
            for subdomain in subdomains:
                subdomain_name = subdomain if isinstance(subdomain, str) else subdomain.get('domain', '')
                
                if subdomain_name and subdomain_name not in live_host_names:
                    # Potential subdomain takeover
                    finding = Finding(
                        title=f"Potential Subdomain Takeover: {subdomain_name}",
                        severity=SeverityLevel.HIGH,
                        description=f"Subdomain {subdomain_name} points to non-responsive or unclaimed resource",
                        impact="Subdomain takeover could allow attackers to serve malicious content under the target domain",
                        affected_url=f"https://{subdomain_name}",
                        evidence={
                            'subdomain': subdomain_name,
                            'dns_status': 'pointing to unclaimed resource',
                            'http_status': 'non-responsive'
                        },
                        recommendation="Verify DNS configuration and remove unused DNS records",
                        discovery_method="Subdomain Enumeration Analysis"
                    )
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error analyzing subdomain risks: {e}")
            return []
    
    def _assess_service_severity(self, service_name: str, version: str, port: int) -> SeverityLevel:
        """Assess the severity of an exposed service"""
        
        # High-risk services
        if service_name.lower() in ['ftp', 'telnet', 'rlogin', 'mysql', 'postgresql', 'mongodb']:
            return SeverityLevel.HIGH
        
        # Medium-risk services
        if service_name.lower() in ['ssh', 'rdp', 'vnc', 'smb', 'smtp', 'pop3', 'imap']:
            return SeverityLevel.MEDIUM
        
        # Common services on non-standard ports
        if service_name.lower() in ['http', 'https'] and port not in [80, 443, 8080, 8443]:
            return SeverityLevel.MEDIUM
        
        # Default to low
        return SeverityLevel.LOW
    
    def _generate_impact_description(self, vuln: Dict[str, Any], severity: SeverityLevel) -> str:
        """Generate impact description for a vulnerability"""
        
        template_id = vuln.get('template_id', '').lower()
        
        # Common vulnerability impacts
        if 'xss' in template_id:
            return "Cross-site scripting vulnerability allows attackers to execute malicious scripts in user browsers, potentially leading to session hijacking, data theft, or defacement."
        elif 'sqli' in template_id or 'sql-injection' in template_id:
            return "SQL injection vulnerability allows attackers to manipulate database queries, potentially leading to data breaches, data modification, or complete system compromise."
        elif 'rce' in template_id or 'command-injection' in template_id:
            return "Remote code execution vulnerability allows attackers to execute arbitrary commands on the server, potentially leading to complete system compromise."
        elif 'lfi' in template_id or 'directory-traversal' in template_id:
            return "Local file inclusion vulnerability allows attackers to read sensitive files from the server, potentially exposing configuration files, credentials, or source code."
        elif 'ssrf' in template_id:
            return "Server-side request forgery vulnerability allows attackers to make requests from the server to internal resources, potentially exposing internal services or data."
        else:
            # Generic impact based on severity
            if severity == SeverityLevel.CRITICAL:
                return "Critical security vulnerability that could lead to complete system compromise or significant data breach."
            elif severity == SeverityLevel.HIGH:
                return "High-severity security vulnerability that poses significant risk to system security and data integrity."
            elif severity == SeverityLevel.MEDIUM:
                return "Medium-severity security vulnerability that could be exploited to gain unauthorized access or information."
            else:
                return "Security vulnerability that may provide attackers with additional attack vectors or information disclosure."
    
    def _generate_vulnerability_recommendation(self, vuln: Dict[str, Any], severity: SeverityLevel) -> str:
        """Generate remediation recommendation for a vulnerability"""
        
        template_id = vuln.get('template_id', '').lower()
        
        # Specific recommendations
        if 'xss' in template_id:
            return "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers to mitigate XSS attacks."
        elif 'sqli' in template_id:
            return "Use parameterized queries or prepared statements. Implement proper input validation and avoid dynamic SQL construction."
        elif 'rce' in template_id:
            return "Implement strict input validation and avoid executing user-controlled data. Use secure coding practices and sandboxing."
        elif 'lfi' in template_id:
            return "Implement proper access controls and input validation. Avoid user-controlled file paths and use whitelisting."
        else:
            return f"Review and patch the vulnerability identified by template {vuln.get('template_id', 'unknown')}. Implement security best practices and regular security testing."
    
    def _generate_service_impact(self, service_name: str, port: int, version: str) -> str:
        """Generate impact description for an exposed service"""
        
        if service_name.lower() in ['ftp', 'telnet']:
            return "Unencrypted protocol exposes credentials and data to interception. High risk of credential compromise."
        elif service_name.lower() == 'ssh':
            return "SSH service exposure may allow brute-force attacks against user credentials."
        elif service_name.lower() in ['mysql', 'postgresql', 'mongodb']:
            return "Database service exposure may allow unauthorized access to sensitive data if misconfigured."
        elif service_name.lower() == 'rdp':
            return "Remote desktop exposure increases attack surface and may allow lateral movement if compromised."
        else:
            return f"Service exposure on port {port} increases attack surface and may provide additional attack vectors."
    
    def _generate_service_recommendation(self, service_name: str, port: int) -> str:
        """Generate recommendation for an exposed service"""
        
        if service_name.lower() in ['ftp', 'telnet']:
            return "Replace with secure alternatives (SFTP, SSH). If required, restrict access using firewalls and VPNs."
        elif service_name.lower() == 'ssh':
            return "Implement key-based authentication, disable password authentication, and use fail2ban for brute-force protection."
        elif service_name.lower() in ['mysql', 'postgresql', 'mongodb']:
            return "Restrict database access to authorized hosts only. Use strong authentication and encrypt connections."
        else:
            return f"Evaluate if service on port {port} needs to be publicly accessible. Implement access controls and monitoring."
    
    def _generate_poc_for_vulnerability(self, vuln: Dict[str, Any]) -> str:
        """Generate proof-of-concept for a vulnerability"""
        
        template_id = vuln.get('template_id', '')
        matched_at = vuln.get('matched_at', '')
        
        # Basic curl command
        if matched_at:
            return f"curl -X GET '{matched_at}' -H 'User-Agent: Mozilla/5.0'"
        else:
            return f"Vulnerability detected using Nuclei template: {template_id}"
    
    async def _generate_ai_insights(self, statistics: ScanStatistics, findings: List[Finding]) -> Optional[Dict[str, Any]]:
        """Generate AI-powered insights for the report"""
        
        try:
            if not self.ai_client or not self.ai_client.is_available():
                return None
            
            # Prepare data for AI analysis
            findings_summary = []
            for finding in findings[:10]:  # Limit to top 10 findings
                findings_summary.append({
                    'title': finding.title,
                    'severity': finding.severity.value,
                    'description': finding.description,
                    'affected_url': finding.affected_url
                })
            
            analysis_data = {
                'target': statistics.target,
                'findings_count': len(findings),
                'critical_count': statistics.critical_severity_count,
                'high_count': statistics.high_severity_count,
                'findings': findings_summary
            }
            
            # Generate AI insights
            if hasattr(self.ai_client, 'analyze_security_report'):
                return await self.ai_client.analyze_security_report(analysis_data)
            elif hasattr(self.ai_client, 'complete'):
                prompt = self._build_ai_analysis_prompt(analysis_data)
                response = await self.ai_client.complete(prompt)
                return self._parse_ai_insights(response)
            
            return None
            
        except Exception as e:
            logger.error(f"Error generating AI insights: {e}")
            return None
    
    def _build_ai_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for AI analysis of security findings"""
        
        prompt = f"""
Analyze the following security assessment results for {data['target']}:

SUMMARY:
- Total Findings: {data['findings_count']}
- Critical: {data['critical_count']}
- High: {data['high_count']}

TOP FINDINGS:
"""
        
        for finding in data['findings']:
            prompt += f"- {finding['severity'].upper()}: {finding['title']} at {finding['affected_url']}\n"
        
        prompt += """

Please provide:
1. Overall security posture assessment (Excellent/Good/Poor/Critical)
2. Top 3 priority actions for remediation
3. Business risk assessment
4. Compliance considerations (if applicable)
5. Strategic security recommendations

Format response as JSON with keys: security_posture, priority_actions, business_risk, compliance_notes, strategic_recommendations
"""
        
        return prompt
    
    def _parse_ai_insights(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse AI response for insights"""
        
        try:
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            else:
                # Fallback parsing
                return {
                    'security_posture': 'Unknown',
                    'priority_actions': ['Review critical findings', 'Implement security controls', 'Monitor for threats'],
                    'business_risk': 'Moderate risk identified',
                    'strategic_recommendations': ['Regular security assessments', 'Security training', 'Incident response planning']
                }
        except Exception as e:
            logger.error(f"Error parsing AI insights: {e}")
            return None
    
    async def _get_change_data(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Get change detection data for the workspace"""
        
        try:
            # This would integrate with the change detector
            # For now, return None - change reports are separate
            return None
        except Exception as e:
            logger.error(f"Error getting change data: {e}")
            return None
    
    def _generate_recommendations(
        self, 
        statistics: ScanStatistics, 
        findings: List[Finding], 
        ai_insights: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Critical findings recommendations
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical_findings:
            recommendations.append(f"🚨 URGENT: Address {len(critical_findings)} critical security vulnerabilities immediately")
        
        # High severity recommendations
        high_findings = [f for f in findings if f.severity == SeverityLevel.HIGH]
        if high_findings:
            recommendations.append(f"⚠️ HIGH PRIORITY: Remediate {len(high_findings)} high-severity findings within 48 hours")
        
        # Service-specific recommendations
        if statistics.vulnerabilities_found == 0 and statistics.open_ports > 10:
            recommendations.append("🔍 Consider implementing additional vulnerability scanning for exposed services")
        
        # AI-generated recommendations
        if ai_insights and 'priority_actions' in ai_insights:
            for action in ai_insights['priority_actions'][:3]:
                recommendations.append(f"🤖 AI Recommendation: {action}")
        
        # General security recommendations
        recommendations.extend([
            "🛡️ Implement regular security monitoring and alerting",
            "📋 Establish incident response procedures for security events",
            "🎓 Provide security awareness training for development teams",
            "🔄 Schedule regular follow-up security assessments"
        ])
        
        return recommendations
    
    async def _generate_executive_summary_text(
        self, 
        statistics: ScanStatistics, 
        findings: List[Finding], 
        ai_insights: Optional[Dict[str, Any]]
    ) -> str:
        """Generate executive summary text"""
        
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        # Overall risk assessment
        if critical_count > 0:
            risk_level = "HIGH RISK"
            risk_description = "Critical security vulnerabilities require immediate attention"
        elif high_count > 3:
            risk_level = "ELEVATED RISK"
            risk_description = "Multiple high-severity findings pose significant security concerns"
        elif high_count > 0:
            risk_level = "MODERATE RISK"
            risk_description = "High-priority security issues identified that should be addressed promptly"
        else:
            risk_level = "LOW RISK"
            risk_description = "No critical security issues identified in this assessment"
        
        summary = f"""
Security Assessment Summary for {statistics.target}

OVERALL SECURITY POSTURE: {risk_level}

{risk_description}

KEY FINDINGS:
• {statistics.vulnerabilities_found} security vulnerabilities identified
• {statistics.subdomains_found} subdomains discovered 
• {statistics.live_hosts} live services detected
• {statistics.open_ports} network services exposed

RISK BREAKDOWN:
• Critical: {critical_count} findings
• High: {high_count} findings  
• Medium: {statistics.medium_severity_count} findings
• Low: {statistics.low_severity_count} findings

IMMEDIATE ACTIONS REQUIRED:
"""
        
        if critical_count > 0:
            summary += f"• Address {critical_count} critical vulnerabilities immediately\n"
        if high_count > 0:
            summary += f"• Remediate {high_count} high-severity findings within 48 hours\n"
        
        summary += "• Review all findings and implement recommended security controls\n"
        summary += "• Establish ongoing security monitoring and assessment processes\n"
        
        return summary.strip()
    
    async def _generate_executive_summary(
        self, 
        report_data: ReportData, 
        format: ReportFormat, 
        options: Dict[str, Any]
    ) -> str:
        """Generate executive summary report"""
        
        if format == ReportFormat.HTML:
            return self._generate_executive_html(report_data, options)
        else:
            return self._generate_executive_markdown(report_data, options)
    
    def _generate_executive_markdown(self, report_data: ReportData, options: Dict[str, Any]) -> str:
        """Generate executive summary in markdown format"""
        
        stats = report_data.statistics
        findings = report_data.findings
        
        # Risk assessment
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        if critical_count > 0:
            risk_emoji = "🚨"
            risk_level = "HIGH RISK"
        elif high_count > 2:
            risk_emoji = "⚠️"
            risk_level = "ELEVATED RISK"
        elif high_count > 0:
            risk_emoji = "🔶"
            risk_level = "MODERATE RISK"
        else:
            risk_emoji = "✅"
            risk_level = "LOW RISK"
        
        content = f"""# Executive Security Summary

**Target:** {stats.target}  
**Assessment Date:** {stats.scan_date[:10]}  
**Overall Risk Level:** {risk_emoji} **{risk_level}**

## Executive Overview

{report_data.executive_summary}

## Key Metrics

| Metric | Count | Status |
|--------|-------|--------|
| **Security Vulnerabilities** | {stats.vulnerabilities_found} | {self._get_status_emoji(stats.vulnerabilities_found, 'vulns')} |
| **Critical Findings** | {critical_count} | {self._get_status_emoji(critical_count, 'critical')} |
| **High Priority Issues** | {high_count} | {self._get_status_emoji(high_count, 'high')} |
| **Subdomains Discovered** | {stats.subdomains_found} | ℹ️ |
| **Live Services** | {stats.live_hosts} | ℹ️ |
| **Assessment Tools Used** | {len(stats.tools_used)} | ✅ |

## Critical Business Impact

"""
        
        if critical_count > 0:
            content += f"🚨 **IMMEDIATE ACTION REQUIRED:** {critical_count} critical security vulnerabilities pose significant business risk and require immediate remediation.\n\n"
        
        if high_count > 0:
            content += f"⚠️ **HIGH PRIORITY:** {high_count} high-severity security issues should be addressed within 48 hours to prevent potential security incidents.\n\n"
        
        # Top critical findings
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL][:3]
        if critical_findings:
            content += "## Most Critical Security Issues\n\n"
            for i, finding in enumerate(critical_findings, 1):
                content += f"{i}. **{finding.title}**\n"
                content += f"   - **Impact:** {finding.impact}\n"
                content += f"   - **Location:** {finding.affected_url}\n"
                content += f"   - **Action Required:** {finding.recommendation}\n\n"
        
        # Recommendations
        content += "## Executive Recommendations\n\n"
        for i, rec in enumerate(report_data.recommendations[:5], 1):
            content += f"{i}. {rec}\n"
        
        # AI insights
        if report_data.ai_insights:
            content += "\n## Strategic Security Assessment\n\n"
            ai_insights = report_data.ai_insights
            if 'security_posture' in ai_insights:
                content += f"**Overall Security Posture:** {ai_insights['security_posture']}\n\n"
            if 'business_risk' in ai_insights:
                content += f"**Business Risk Analysis:** {ai_insights['business_risk']}\n\n"
        
        content += f"""
---
*This executive summary provides a high-level overview of security findings. Technical teams should review the complete technical report for detailed remediation guidance.*

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by BugHound Security Platform
"""
        
        return content
    
    def _generate_executive_html(self, report_data: ReportData, options: Dict[str, Any]) -> str:
        """Generate executive summary in HTML format"""
        
        # This would use HTML templates for professional formatting
        # For now, convert markdown to basic HTML structure
        markdown_content = self._generate_executive_markdown(report_data, options)
        
        # Basic markdown to HTML conversion
        html_content = markdown_content.replace('# ', '<h1>').replace('\n', '</h1>\n', 1)
        html_content = html_content.replace('## ', '<h2>').replace('\n', '</h2>\n')
        html_content = html_content.replace('**', '<strong>', 1).replace('**', '</strong>', 1)
        
        # Wrap in HTML document
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Executive Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .risk-high {{ color: #d32f2f; }}
        .risk-medium {{ color: #f57c00; }}
        .risk-low {{ color: #388e3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
    
    async def _generate_technical_report(
        self, 
        report_data: ReportData, 
        format: ReportFormat, 
        options: Dict[str, Any]
    ) -> str:
        """Generate detailed technical report"""
        
        stats = report_data.statistics
        findings = report_data.findings
        
        content = f"""# Technical Security Assessment Report

**Target:** {stats.target}  
**Assessment Date:** {stats.scan_date[:10]}  
**Workspace ID:** {stats.workspace_id}  
**Assessment Duration:** {stats.duration_minutes} minutes  

## Assessment Overview

This technical report provides detailed information about security vulnerabilities and findings discovered during the automated security assessment of {stats.target}.

### Tools and Methodology

**Reconnaissance Tools Used:**
"""
        
        for tool in stats.tools_used:
            content += f"- {tool.title()}\n"
        
        content += f"""

### Summary Statistics

- **Subdomains Discovered:** {stats.subdomains_found}
- **Live Hosts Identified:** {stats.live_hosts}
- **Open Ports Found:** {stats.open_ports}
- **Security Vulnerabilities:** {stats.vulnerabilities_found}

### Vulnerability Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {stats.critical_severity_count} | {self._calculate_percentage(stats.critical_severity_count, stats.vulnerabilities_found)}% |
| High | {stats.high_severity_count} | {self._calculate_percentage(stats.high_severity_count, stats.vulnerabilities_found)}% |
| Medium | {stats.medium_severity_count} | {self._calculate_percentage(stats.medium_severity_count, stats.vulnerabilities_found)}% |
| Low | {stats.low_severity_count} | {self._calculate_percentage(stats.low_severity_count, stats.vulnerabilities_found)}% |

## Detailed Findings

"""
        
        # Group findings by severity
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            severity_findings = [f for f in findings if f.severity == severity]
            
            if severity_findings:
                content += f"### {severity.value.upper()} Severity Findings\n\n"
                
                for i, finding in enumerate(severity_findings, 1):
                    content += f"#### {i}. {finding.title}\n\n"
                    content += f"**Severity:** {finding.severity.value.upper()}\n"
                    content += f"**Affected URL:** {finding.affected_url}\n\n"
                    
                    if finding.cve_references:
                        content += f"**CVE References:** {', '.join(finding.cve_references)}\n\n"
                    
                    content += f"**Description:**\n{finding.description}\n\n"
                    content += f"**Impact:**\n{finding.impact}\n\n"
                    
                    if finding.proof_of_concept:
                        content += f"**Proof of Concept:**\n```\n{finding.proof_of_concept}\n```\n\n"
                    
                    content += f"**Recommendation:**\n{finding.recommendation}\n\n"
                    
                    if finding.evidence:
                        content += "**Technical Evidence:**\n"
                        for key, value in finding.evidence.items():
                            if value and key != 'request' and key != 'response':  # Exclude large data
                                content += f"- {key.title()}: {value}\n"
                        content += "\n"
                    
                    content += "---\n\n"
        
        # Recommendations section
        content += "## Remediation Recommendations\n\n"
        for i, rec in enumerate(report_data.recommendations, 1):
            content += f"{i}. {rec}\n"
        
        # Technical appendix
        content += f"""

## Technical Appendix

### Assessment Methodology

This security assessment was performed using automated reconnaissance and vulnerability scanning techniques:

1. **Subdomain Enumeration** - Passive and active discovery of subdomains
2. **Live Host Detection** - Identification of active web services
3. **Port Scanning** - Discovery of exposed network services
4. **Vulnerability Scanning** - Template-based security testing
5. **Risk Analysis** - Severity assessment and impact analysis

### Risk Rating Methodology

Vulnerabilities are rated using the following criteria:

- **Critical:** Immediate risk of complete system compromise
- **High:** Significant security risk requiring prompt attention
- **Medium:** Moderate security concern that should be addressed
- **Low:** Minor security issue with limited impact

---
*Report generated by BugHound Security Platform on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return content
    
    async def _generate_bug_bounty_report(
        self, 
        report_data: ReportData, 
        format: ReportFormat, 
        options: Dict[str, Any]
    ) -> str:
        """Generate bug bounty submission ready report"""
        
        platform = options.get('platform', 'hackerone')
        platform_config = self.platform_configs.get(platform, self.platform_configs['hackerone'])
        
        # Only include high and critical findings for bug bounty
        bounty_findings = [f for f in report_data.findings 
                          if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        if not bounty_findings:
            return "No high or critical severity vulnerabilities suitable for bug bounty submission found."
        
        content = f"# Security Vulnerabilities Report - {report_data.statistics.target}\n\n"
        content += f"**Target:** {report_data.statistics.target}\n"
        content += f"**Discovery Date:** {report_data.statistics.scan_date[:10]}\n"
        content += f"**Report Date:** {datetime.now().strftime('%Y-%m-%d')}\n\n"
        
        for i, finding in enumerate(bounty_findings, 1):
            content += platform_config['title_format'].format(title=finding.title) + "\n\n"
            content += platform_config['severity_field'].format(severity=finding.severity.value.title()) + "\n\n"
            
            # Description
            content += "**Summary**\n"
            content += f"{finding.description}\n\n"
            
            # Impact section
            content += platform_config['impact_section'].format(impact=finding.impact) + "\n\n"
            
            # Proof of concept section
            if finding.proof_of_concept:
                content += platform_config['poc_section'].format(poc=finding.proof_of_concept) + "\n\n"
            
            # Technical details
            content += "**Technical Details**\n"
            content += f"- **Affected URL:** {finding.affected_url}\n"
            content += f"- **Discovery Method:** {finding.discovery_method}\n"
            
            if finding.cve_references:
                content += f"- **CVE References:** {', '.join(finding.cve_references)}\n"
            
            content += "\n"
            
            # Recommendation section
            content += platform_config['recommendation_section'].format(recommendation=finding.recommendation) + "\n\n"
            
            if i < len(bounty_findings):
                content += "---\n\n"
        
        # Footer
        content += f"""
**Disclaimer:** This report was generated using automated security testing tools. Manual verification may be required for some findings.

**Testing Authorization:** This assessment was conducted on assets under authorized scope.

**Report Generated By:** BugHound Security Platform
"""
        
        return content
    
    async def _generate_change_report(
        self, 
        report_data: ReportData, 
        format: ReportFormat, 
        options: Dict[str, Any]
    ) -> str:
        """Generate change detection report"""
        
        # This would integrate with change detection data
        # For now, return basic template
        
        content = f"""# Security Change Report - {report_data.statistics.target}

**Target:** {report_data.statistics.target}  
**Current Scan:** {report_data.statistics.scan_date[:10]}  
**Workspace:** {report_data.statistics.workspace_id}

## Change Summary

This report shows changes in the security posture since the last assessment.

### Current Assessment Results

- **Vulnerabilities Found:** {report_data.statistics.vulnerabilities_found}
- **Critical Findings:** {report_data.statistics.critical_severity_count}
- **High Priority Issues:** {report_data.statistics.high_severity_count}

### Change Analysis

*Change detection requires multiple scans for comparison. Run additional scans to see detailed change analysis.*

### Current Findings

"""
        
        # Show current findings
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            severity_findings = [f for f in report_data.findings if f.severity == severity]
            if severity_findings:
                content += f"#### {severity.value.upper()} Severity\n\n"
                for finding in severity_findings:
                    content += f"- {finding.title} at {finding.affected_url}\n"
                content += "\n"
        
        content += """
### Recommendations

1. 🔄 Schedule regular security assessments to enable change tracking
2. 📊 Monitor security metrics over time
3. 🚨 Set up alerts for new critical findings
4. 📈 Track security improvement progress

---
*Complete change analysis available after multiple scans*
"""
        
        return content
    
    def _calculate_percentage(self, count: int, total: int) -> int:
        """Calculate percentage with zero division protection"""
        if total == 0:
            return 0
        return round((count / total) * 100)
    
    def _get_status_emoji(self, count: int, finding_type: str) -> str:
        """Get status emoji based on count and type"""
        if finding_type == 'critical':
            return "🚨" if count > 0 else "✅"
        elif finding_type == 'high':
            return "⚠️" if count > 2 else "🔶" if count > 0 else "✅"
        elif finding_type == 'vulns':
            return "⚠️" if count > 5 else "🔶" if count > 0 else "✅"
        else:
            return "ℹ️"
    
    async def save_report(self, workspace_id: str, report_content: str, report_metadata: Dict[str, Any]) -> str:
        """Save generated report to workspace"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                raise ValueError(f"Workspace {workspace_id} not found")
            
            # Create reports directory
            reports_dir = workspace.workspace_path / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Generate filename
            report_type = report_metadata.get('report_type', 'report')
            report_format = report_metadata.get('format', 'md')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_{timestamp}.{report_format}"
            
            # Save report
            report_path = reports_dir / filename
            with open(report_path, 'w') as f:
                f.write(report_content)
            
            # Save metadata
            metadata_path = reports_dir / f"{report_type}_{timestamp}_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(report_metadata, f, indent=2)
            
            logger.info(f"Report saved to {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise


# Utility functions for report formatting
def format_severity_badge(severity: SeverityLevel) -> str:
    """Format severity as badge"""
    badges = {
        SeverityLevel.CRITICAL: "🚨 CRITICAL",
        SeverityLevel.HIGH: "🔥 HIGH",
        SeverityLevel.MEDIUM: "⚠️ MEDIUM",
        SeverityLevel.LOW: "ℹ️ LOW",
        SeverityLevel.INFO: "📋 INFO"
    }
    return badges.get(severity, "❓ UNKNOWN")


def sanitize_for_platform(text: str, platform: str = "hackerone") -> str:
    """Sanitize text for specific bug bounty platforms"""
    
    # Remove potentially sensitive information
    text = re.sub(r'internal[\w\-\.]*', '[REDACTED]', text, flags=re.IGNORECASE)
    text = re.sub(r'admin[\w\-\.]*', '[ADMIN-ENDPOINT]', text, flags=re.IGNORECASE)
    
    # Platform-specific formatting
    if platform == "hackerone":
        # HackerOne specific formatting
        text = text.replace("**", "")  # Remove bold markdown
        
    return text