#!/usr/bin/env python3
"""
Change Detection Engine for BugHound

Compares reconnaissance results between different scans to identify:
- New attack surface (subdomains, services, vulnerabilities)
- Removed/fixed items 
- Changes in security posture
- Risk delta analysis
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes that can be detected"""
    NEW = "new"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class FindingType(Enum):
    """Types of findings that can be tracked"""
    SUBDOMAIN = "subdomain"
    LIVE_HOST = "live_host"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    TECHNOLOGY = "technology"


@dataclass
class Finding:
    """Represents a security finding that can be tracked"""
    finding_type: FindingType
    identifier: str  # Unique identifier for the finding
    data: Dict[str, Any]  # Full finding data
    timestamp: str
    workspace_id: str
    
    def __hash__(self):
        return hash((self.finding_type, self.identifier))
    
    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return self.finding_type == other.finding_type and self.identifier == other.identifier


@dataclass
class Change:
    """Represents a change between two scans"""
    change_type: ChangeType
    finding_type: FindingType
    identifier: str
    old_data: Optional[Dict[str, Any]] = None
    new_data: Optional[Dict[str, Any]] = None
    significance: str = "medium"  # low, medium, high, critical
    description: str = ""
    risk_impact: str = ""  # Risk assessment of the change


@dataclass
class ChangeReport:
    """Comprehensive change report between two scans"""
    baseline_workspace_id: str
    current_workspace_id: str
    baseline_date: str
    current_date: str
    target: str
    changes: List[Change]
    summary_stats: Dict[str, Any]
    risk_delta: str  # Overall risk change: increased, decreased, unchanged
    recommendations: List[str]


class ChangeDetector:
    """Detects and analyzes changes between reconnaissance scans"""
    
    def __init__(self, workspace_manager, ai_client=None):
        """
        Initialize change detector
        
        Args:
            workspace_manager: WorkspaceManager instance for data access
            ai_client: Optional AI client for enhanced analysis
        """
        self.workspace_manager = workspace_manager
        self.ai_client = ai_client
        
        # Risk scoring weights for different finding types
        self.risk_weights = {
            FindingType.SUBDOMAIN: 1,
            FindingType.LIVE_HOST: 2,
            FindingType.PORT: 3,
            FindingType.VULNERABILITY: 5,
            FindingType.TECHNOLOGY: 2
        }
    
    async def compare_workspaces(
        self, 
        baseline_workspace_id: str, 
        current_workspace_id: str
    ) -> Optional[ChangeReport]:
        """
        Compare two workspaces and generate a change report
        
        Args:
            baseline_workspace_id: ID of the baseline (older) workspace
            current_workspace_id: ID of the current (newer) workspace
            
        Returns:
            ChangeReport object or None if comparison failed
        """
        
        try:
            logger.info(f"Comparing workspaces: {baseline_workspace_id} -> {current_workspace_id}")
            
            # Get workspace data
            baseline_workspace = await self.workspace_manager.get_workspace(baseline_workspace_id)
            current_workspace = await self.workspace_manager.get_workspace(current_workspace_id)
            
            if not baseline_workspace or not current_workspace:
                logger.error("One or both workspaces not found")
                return None
            
            # Validate targets match
            if baseline_workspace.metadata.target != current_workspace.metadata.target:
                logger.warning(f"Target mismatch: {baseline_workspace.metadata.target} vs {current_workspace.metadata.target}")
            
            # Extract findings from both workspaces
            baseline_findings = await self._extract_findings(baseline_workspace_id)
            current_findings = await self._extract_findings(current_workspace_id)
            
            # Generate changes
            changes = self._identify_changes(baseline_findings, current_findings)
            
            # Calculate summary statistics
            summary_stats = self._calculate_summary_stats(changes, baseline_findings, current_findings)
            
            # Assess risk delta
            risk_delta = self._assess_risk_delta(changes)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(changes, summary_stats)
            
            # Enhance with AI analysis if available
            if self.ai_client and self.ai_client.is_available():
                try:
                    ai_insights = await self._analyze_changes_with_ai(changes, summary_stats, current_workspace.metadata.target)
                    if ai_insights:
                        # Update significance and recommendations based on AI analysis
                        changes = self._apply_ai_insights(changes, ai_insights)
                        recommendations.extend(ai_insights.get('recommendations', []))
                        
                        # Update risk delta if AI provides better assessment
                        ai_risk_delta = ai_insights.get('risk_assessment')
                        if ai_risk_delta:
                            risk_delta = ai_risk_delta
                            
                except Exception as e:
                    logger.warning(f"AI analysis failed, using standard analysis: {e}")
            
            # Create change report
            report = ChangeReport(
                baseline_workspace_id=baseline_workspace_id,
                current_workspace_id=current_workspace_id,
                baseline_date=baseline_workspace.metadata.created_date,
                current_date=current_workspace.metadata.created_date,
                target=current_workspace.metadata.target,
                changes=changes,
                summary_stats=summary_stats,
                risk_delta=risk_delta,
                recommendations=recommendations
            )
            
            logger.info(f"Change detection completed: {len(changes)} changes found")
            return report
            
        except Exception as e:
            logger.error(f"Error comparing workspaces: {e}")
            return None
    
    async def monitor_target(self, target: str) -> Optional[ChangeReport]:
        """
        Monitor a target by comparing the latest scan with the previous one
        
        Args:
            target: Target domain to monitor
            
        Returns:
            ChangeReport showing changes since last scan
        """
        
        try:
            # Find workspaces for this target
            workspaces = await self.workspace_manager.search_workspaces(target)
            
            if len(workspaces) < 2:
                logger.info(f"Not enough scans for target {target} to perform comparison")
                return None
            
            # Get the two most recent workspaces
            current_workspace = workspaces[0]  # Most recent
            baseline_workspace = workspaces[1]  # Previous
            
            return await self.compare_workspaces(
                baseline_workspace.metadata.workspace_id,
                current_workspace.metadata.workspace_id
            )
            
        except Exception as e:
            logger.error(f"Error monitoring target {target}: {e}")
            return None
    
    async def get_new_findings(
        self, 
        baseline_workspace_id: str, 
        current_workspace_id: str,
        finding_types: Optional[List[FindingType]] = None
    ) -> Dict[FindingType, List[Finding]]:
        """
        Get only new findings between two scans
        
        Args:
            baseline_workspace_id: Baseline workspace ID
            current_workspace_id: Current workspace ID
            finding_types: Optional filter for specific finding types
            
        Returns:
            Dictionary of finding types to new findings
        """
        
        try:
            report = await self.compare_workspaces(baseline_workspace_id, current_workspace_id)
            if not report:
                return {}
            
            new_findings = {}
            
            for change in report.changes:
                if change.change_type == ChangeType.NEW:
                    if finding_types and change.finding_type not in finding_types:
                        continue
                    
                    if change.finding_type not in new_findings:
                        new_findings[change.finding_type] = []
                    
                    # Create finding object from change
                    finding = Finding(
                        finding_type=change.finding_type,
                        identifier=change.identifier,
                        data=change.new_data or {},
                        timestamp=report.current_date,
                        workspace_id=current_workspace_id
                    )
                    new_findings[change.finding_type].append(finding)
            
            return new_findings
            
        except Exception as e:
            logger.error(f"Error getting new findings: {e}")
            return {}
    
    async def _extract_findings(self, workspace_id: str) -> Set[Finding]:
        """Extract all findings from a workspace"""
        
        findings = set()
        
        try:
            # Get all results from workspace
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            if not all_results:
                return findings
            
            workspace_info = await self.workspace_manager.get_workspace(workspace_id)
            timestamp = workspace_info.metadata.created_date if workspace_info else datetime.now().isoformat()
            
            # Extract subdomains
            for tool_name in ['subfinder', 'altdns']:
                if tool_name in all_results['tools']:
                    tool_data = all_results['tools'][tool_name]
                    results = tool_data.get('results', {})
                    
                    subdomains = results.get('subdomains', []) or results.get('generated_subdomains', [])
                    for subdomain in subdomains:
                        finding = Finding(
                            finding_type=FindingType.SUBDOMAIN,
                            identifier=subdomain,
                            data={'subdomain': subdomain, 'source': tool_name},
                            timestamp=timestamp,
                            workspace_id=workspace_id
                        )
                        findings.add(finding)
            
            # Extract live hosts
            if 'httpx' in all_results['tools']:
                httpx_data = all_results['tools']['httpx']
                results = httpx_data.get('results', {})
                
                for host in results.get('live_hosts', []):
                    host_id = host.get('host') or host.get('url', '')
                    if host_id:
                        finding = Finding(
                            finding_type=FindingType.LIVE_HOST,
                            identifier=host_id,
                            data=host,
                            timestamp=timestamp,
                            workspace_id=workspace_id
                        )
                        findings.add(finding)
            
            # Extract ports
            if 'nmap' in all_results['tools']:
                nmap_data = all_results['tools']['nmap']
                results = nmap_data.get('results', {})
                
                for service in results.get('services', []):
                    host = service.get('host', '')
                    port = service.get('port', 0)
                    port_id = f"{host}:{port}"
                    
                    finding = Finding(
                        finding_type=FindingType.PORT,
                        identifier=port_id,
                        data=service,
                        timestamp=timestamp,
                        workspace_id=workspace_id
                    )
                    findings.add(finding)
            
            # Extract vulnerabilities
            if 'nuclei' in all_results['tools']:
                nuclei_data = all_results['tools']['nuclei']
                results = nuclei_data.get('results', {})
                
                for vuln in results.get('vulnerabilities', []):
                    vuln_id = f"{vuln.get('matched_at', '')}-{vuln.get('template_id', '')}"
                    
                    finding = Finding(
                        finding_type=FindingType.VULNERABILITY,
                        identifier=vuln_id,
                        data=vuln,
                        timestamp=timestamp,
                        workspace_id=workspace_id
                    )
                    findings.add(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error extracting findings from workspace {workspace_id}: {e}")
            return findings
    
    def _identify_changes(self, baseline_findings: Set[Finding], current_findings: Set[Finding]) -> List[Change]:
        """Identify changes between two sets of findings"""
        
        changes = []
        
        # Create lookup dictionaries for efficient comparison
        baseline_lookup = {(f.finding_type, f.identifier): f for f in baseline_findings}
        current_lookup = {(f.finding_type, f.identifier): f for f in current_findings}
        
        # Find new findings (in current but not in baseline)
        for key, finding in current_lookup.items():
            if key not in baseline_lookup:
                change = Change(
                    change_type=ChangeType.NEW,
                    finding_type=finding.finding_type,
                    identifier=finding.identifier,
                    new_data=finding.data,
                    significance=self._assess_significance(finding.finding_type, ChangeType.NEW),
                    description=f"New {finding.finding_type.value}: {finding.identifier}",
                    risk_impact=self._assess_risk_impact(finding.finding_type, ChangeType.NEW)
                )
                changes.append(change)
        
        # Find removed findings (in baseline but not in current)
        for key, finding in baseline_lookup.items():
            if key not in current_lookup:
                change = Change(
                    change_type=ChangeType.REMOVED,
                    finding_type=finding.finding_type,
                    identifier=finding.identifier,
                    old_data=finding.data,
                    significance=self._assess_significance(finding.finding_type, ChangeType.REMOVED),
                    description=f"Removed {finding.finding_type.value}: {finding.identifier}",
                    risk_impact=self._assess_risk_impact(finding.finding_type, ChangeType.REMOVED)
                )
                changes.append(change)
        
        # Find modified findings (present in both but different data)
        for key in baseline_lookup.keys() & current_lookup.keys():
            baseline_finding = baseline_lookup[key]
            current_finding = current_lookup[key]
            
            if baseline_finding.data != current_finding.data:
                change = Change(
                    change_type=ChangeType.MODIFIED,
                    finding_type=baseline_finding.finding_type,
                    identifier=baseline_finding.identifier,
                    old_data=baseline_finding.data,
                    new_data=current_finding.data,
                    significance=self._assess_significance(baseline_finding.finding_type, ChangeType.MODIFIED),
                    description=f"Modified {baseline_finding.finding_type.value}: {baseline_finding.identifier}",
                    risk_impact=self._assess_risk_impact(baseline_finding.finding_type, ChangeType.MODIFIED)
                )
                changes.append(change)
        
        return changes
    
    def _assess_significance(self, finding_type: FindingType, change_type: ChangeType) -> str:
        """Assess the significance of a change"""
        
        # Base significance on finding type and change type
        if finding_type == FindingType.VULNERABILITY:
            if change_type == ChangeType.NEW:
                return "critical"
            elif change_type == ChangeType.REMOVED:
                return "high"  # Good news but still significant
        
        elif finding_type == FindingType.PORT:
            if change_type == ChangeType.NEW:
                return "high"
            elif change_type == ChangeType.REMOVED:
                return "medium"
        
        elif finding_type == FindingType.LIVE_HOST:
            if change_type == ChangeType.NEW:
                return "high"
            elif change_type == ChangeType.REMOVED:
                return "medium"
        
        elif finding_type == FindingType.SUBDOMAIN:
            if change_type == ChangeType.NEW:
                return "medium"
            elif change_type == ChangeType.REMOVED:
                return "low"
        
        return "medium"  # Default
    
    def _assess_risk_impact(self, finding_type: FindingType, change_type: ChangeType) -> str:
        """Assess the risk impact of a change"""
        
        if change_type == ChangeType.NEW:
            impact_map = {
                FindingType.VULNERABILITY: "Increased attack surface - new vulnerability discovered",
                FindingType.PORT: "Expanded attack surface - new service exposed",
                FindingType.LIVE_HOST: "New target available - increased reconnaissance scope",
                FindingType.SUBDOMAIN: "Expanded infrastructure - new subdomain discovered",
                FindingType.TECHNOLOGY: "New technology stack identified"
            }
        elif change_type == ChangeType.REMOVED:
            impact_map = {
                FindingType.VULNERABILITY: "Reduced risk - vulnerability appears fixed",
                FindingType.PORT: "Reduced attack surface - service no longer exposed",
                FindingType.LIVE_HOST: "Target decommissioned - reduced attack surface",
                FindingType.SUBDOMAIN: "Infrastructure change - subdomain removed",
                FindingType.TECHNOLOGY: "Technology stack change detected"
            }
        else:  # MODIFIED
            impact_map = {
                FindingType.VULNERABILITY: "Vulnerability details changed - requires review",
                FindingType.PORT: "Service configuration changed",
                FindingType.LIVE_HOST: "Host configuration modified",
                FindingType.SUBDOMAIN: "Subdomain configuration changed",
                FindingType.TECHNOLOGY: "Technology stack updated"
            }
        
        return impact_map.get(finding_type, "Configuration change detected")
    
    def _calculate_summary_stats(
        self, 
        changes: List[Change], 
        baseline_findings: Set[Finding], 
        current_findings: Set[Finding]
    ) -> Dict[str, Any]:
        """Calculate summary statistics for the change report"""
        
        stats = {
            "total_changes": len(changes),
            "new_findings": len([c for c in changes if c.change_type == ChangeType.NEW]),
            "removed_findings": len([c for c in changes if c.change_type == ChangeType.REMOVED]),
            "modified_findings": len([c for c in changes if c.change_type == ChangeType.MODIFIED]),
            "baseline_total": len(baseline_findings),
            "current_total": len(current_findings),
            "net_change": len(current_findings) - len(baseline_findings)
        }
        
        # Changes by finding type
        for finding_type in FindingType:
            type_changes = [c for c in changes if c.finding_type == finding_type]
            stats[f"{finding_type.value}_changes"] = len(type_changes)
            stats[f"new_{finding_type.value}s"] = len([c for c in type_changes if c.change_type == ChangeType.NEW])
            stats[f"removed_{finding_type.value}s"] = len([c for c in type_changes if c.change_type == ChangeType.REMOVED])
        
        # Significance distribution
        for significance in ["critical", "high", "medium", "low"]:
            stats[f"{significance}_significance"] = len([c for c in changes if c.significance == significance])
        
        return stats
    
    def _assess_risk_delta(self, changes: List[Change]) -> str:
        """Assess the overall risk change"""
        
        risk_score = 0
        
        for change in changes:
            weight = self.risk_weights.get(change.finding_type, 1)
            
            if change.change_type == ChangeType.NEW:
                if change.significance == "critical":
                    risk_score += weight * 4
                elif change.significance == "high":
                    risk_score += weight * 3
                elif change.significance == "medium":
                    risk_score += weight * 2
                else:
                    risk_score += weight * 1
            
            elif change.change_type == ChangeType.REMOVED:
                # Removed findings decrease risk
                if change.significance == "critical":
                    risk_score -= weight * 4
                elif change.significance == "high":
                    risk_score -= weight * 3
                elif change.significance == "medium":
                    risk_score -= weight * 2
                else:
                    risk_score -= weight * 1
        
        if risk_score > 5:
            return "significantly_increased"
        elif risk_score > 0:
            return "increased"
        elif risk_score < -5:
            return "significantly_decreased"
        elif risk_score < 0:
            return "decreased"
        else:
            return "unchanged"
    
    def _generate_recommendations(self, changes: List[Change], summary_stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on changes"""
        
        recommendations = []
        
        # Critical vulnerabilities
        critical_vulns = [c for c in changes if c.finding_type == FindingType.VULNERABILITY and c.change_type == ChangeType.NEW and c.significance == "critical"]
        if critical_vulns:
            recommendations.append(f"🚨 URGENT: {len(critical_vulns)} new critical vulnerabilities found - immediate patching required")
        
        # New attack surface
        new_hosts = summary_stats.get("new_live_hosts", 0)
        if new_hosts > 0:
            recommendations.append(f"🎯 Review {new_hosts} new live hosts for security posture")
        
        new_ports = summary_stats.get("new_ports", 0)
        if new_ports > 0:
            recommendations.append(f"🔍 Investigate {new_ports} new open ports for unnecessary services")
        
        new_subdomains = summary_stats.get("new_subdomains", 0)
        if new_subdomains > 5:
            recommendations.append(f"📈 Significant infrastructure expansion: {new_subdomains} new subdomains discovered")
        
        # Fixed issues
        removed_vulns = summary_stats.get("removed_vulnerabilities", 0)
        if removed_vulns > 0:
            recommendations.append(f"✅ Good news: {removed_vulns} previously identified vulnerabilities appear to be fixed")
        
        # General recommendations
        if summary_stats.get("total_changes", 0) > 10:
            recommendations.append("📊 Significant changes detected - recommend comprehensive security review")
        
        if not recommendations:
            recommendations.append("✨ No significant security changes detected since last scan")
        
        return recommendations
    
    async def _analyze_changes_with_ai(self, changes: List[Change], summary_stats: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
        """
        Use AI to analyze changes and provide enhanced insights
        
        Args:
            changes: List of detected changes
            summary_stats: Summary statistics from change analysis
            target: Target domain being analyzed
            
        Returns:
            Dictionary with AI insights or None if analysis failed
        """
        
        try:
            # Prepare change data for AI analysis
            change_data = {
                "target": target,
                "summary": summary_stats,
                "changes": [
                    {
                        "type": c.change_type.value,
                        "finding_type": c.finding_type.value,
                        "identifier": c.identifier,
                        "significance": c.significance,
                        "description": c.description,
                        "risk_impact": c.risk_impact
                    }
                    for c in changes[:50]  # Limit to first 50 changes to avoid token limits
                ]
            }
            
            # Build AI prompt for change analysis
            prompt = self._build_change_analysis_prompt(change_data)
            
            # Get AI analysis
            try:
                # Use existing AI client methods if available
                if hasattr(self.ai_client, 'complete'):
                    response = await self.ai_client.complete(prompt)
                    return self._parse_ai_change_response(response)
                elif hasattr(self.ai_client, 'analyze_changes'):
                    return await self.ai_client.analyze_changes(change_data)
                else:
                    logger.warning("AI client doesn't support change analysis")
                    return None
                    
            except Exception as e:
                logger.error(f"AI client error during change analysis: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Error preparing AI change analysis: {e}")
            return None
    
    def _build_change_analysis_prompt(self, change_data: Dict[str, Any]) -> str:
        """Build a prompt for AI analysis of changes"""
        
        prompt = f"""
Analyze the following security reconnaissance changes for target {change_data['target']}:

SUMMARY STATISTICS:
- Total Changes: {change_data['summary'].get('total_changes', 0)}
- New Findings: {change_data['summary'].get('new_findings', 0)}
- Removed Findings: {change_data['summary'].get('removed_findings', 0)}
- New Subdomains: {change_data['summary'].get('new_subdomains', 0)}
- New Vulnerabilities: {change_data['summary'].get('new_vulnerabilities', 0)}
- New Ports: {change_data['summary'].get('new_ports', 0)}

DETAILED CHANGES:
"""
        
        for change in change_data['changes'][:20]:  # Show first 20 changes
            prompt += f"- {change['type'].upper()}: {change['finding_type']} '{change['identifier']}' (Significance: {change['significance']})\n"
        
        if len(change_data['changes']) > 20:
            prompt += f"... and {len(change_data['changes']) - 20} more changes\n"
        
        prompt += f"""

Please provide:
1. Risk assessment: significantly_increased/increased/unchanged/decreased/significantly_decreased
2. Three most critical findings that require immediate attention
3. Business impact assessment of the changes
4. Strategic recommendations for response
5. Significance re-evaluation: suggest if any changes should be upgraded/downgraded in significance

Format your response as JSON with keys: risk_assessment, critical_findings, business_impact, recommendations, significance_updates
"""
        
        return prompt
    
    def _parse_ai_change_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse AI response for change analysis"""
        
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                return json.loads(json_str)
            else:
                # Fallback: Parse key-value pairs
                insights = {}
                
                # Extract risk assessment
                risk_match = re.search(r'risk_assessment["\']?\s*:\s*["\']?([^"\',\n]+)', response, re.IGNORECASE)
                if risk_match:
                    insights['risk_assessment'] = risk_match.group(1).strip()
                
                # Extract recommendations
                rec_match = re.search(r'recommendations["\']?\s*:\s*\[(.*?)\]', response, re.DOTALL | re.IGNORECASE)
                if rec_match:
                    rec_text = rec_match.group(1)
                    recommendations = [r.strip().strip('"\'') for r in rec_text.split(',') if r.strip()]
                    insights['recommendations'] = recommendations
                
                return insights if insights else None
                
        except Exception as e:
            logger.error(f"Error parsing AI change response: {e}")
            return None
    
    def _apply_ai_insights(self, changes: List[Change], ai_insights: Dict[str, Any]) -> List[Change]:
        """Apply AI insights to update change significance"""
        
        try:
            significance_updates = ai_insights.get('significance_updates', {})
            
            for change in changes:
                change_key = f"{change.finding_type.value}:{change.identifier}"
                if change_key in significance_updates:
                    new_significance = significance_updates[change_key]
                    if new_significance in ['critical', 'high', 'medium', 'low']:
                        logger.info(f"AI updated significance for {change_key}: {change.significance} -> {new_significance}")
                        change.significance = new_significance
            
            return changes
            
        except Exception as e:
            logger.error(f"Error applying AI insights: {e}")
            return changes
    
    async def save_change_outputs(self, report: ChangeReport, workspace_path: Path) -> bool:
        """
        Save change tracking outputs to workspace/monitoring/ directory
        
        Args:
            report: ChangeReport to save outputs for
            workspace_path: Path to the workspace directory
            
        Returns:
            bool: True if outputs were saved successfully
        """
        
        try:
            # Create monitoring directory
            monitoring_dir = workspace_path / "monitoring"
            monitoring_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Saving change outputs to {monitoring_dir}")
            
            # 1. Save new_subdomains.txt
            new_subdomains = [
                c.identifier for c in report.changes 
                if c.change_type == ChangeType.NEW and c.finding_type == FindingType.SUBDOMAIN
            ]
            if new_subdomains:
                subdomain_file = monitoring_dir / "new_subdomains.txt"
                with open(subdomain_file, 'w') as f:
                    f.write(f"# New subdomains discovered - {report.current_date[:10]}\n")
                    f.write(f"# Target: {report.target}\n")
                    f.write(f"# Baseline: {report.baseline_workspace_id}\n")
                    f.write(f"# Current: {report.current_workspace_id}\n\n")
                    for subdomain in new_subdomains:
                        f.write(f"{subdomain}\n")
                logger.info(f"Saved {len(new_subdomains)} new subdomains to {subdomain_file}")
            
            # 2. Save new_vulnerabilities.json
            new_vulnerabilities = [
                {
                    "identifier": c.identifier,
                    "data": c.new_data,
                    "significance": c.significance,
                    "risk_impact": c.risk_impact,
                    "discovered": report.current_date
                }
                for c in report.changes 
                if c.change_type == ChangeType.NEW and c.finding_type == FindingType.VULNERABILITY
            ]
            if new_vulnerabilities:
                vuln_file = monitoring_dir / "new_vulnerabilities.json"
                vuln_data = {
                    "target": report.target,
                    "baseline_workspace": report.baseline_workspace_id,
                    "current_workspace": report.current_workspace_id,
                    "discovery_date": report.current_date,
                    "vulnerabilities": new_vulnerabilities,
                    "summary": {
                        "total_new": len(new_vulnerabilities),
                        "critical": len([v for v in new_vulnerabilities if v["significance"] == "critical"]),
                        "high": len([v for v in new_vulnerabilities if v["significance"] == "high"]),
                        "medium": len([v for v in new_vulnerabilities if v["significance"] == "medium"]),
                        "low": len([v for v in new_vulnerabilities if v["significance"] == "low"])
                    }
                }
                with open(vuln_file, 'w') as f:
                    json.dump(vuln_data, f, indent=2)
                logger.info(f"Saved {len(new_vulnerabilities)} new vulnerabilities to {vuln_file}")
            
            # 3. Save fixed_issues.txt
            fixed_issues = [
                c for c in report.changes 
                if c.change_type == ChangeType.REMOVED and c.finding_type == FindingType.VULNERABILITY
            ]
            if fixed_issues:
                fixed_file = monitoring_dir / "fixed_issues.txt"
                with open(fixed_file, 'w') as f:
                    f.write(f"# Fixed/Resolved Issues - {report.current_date[:10]}\n")
                    f.write(f"# Target: {report.target}\n")
                    f.write(f"# Baseline: {report.baseline_workspace_id}\n")
                    f.write(f"# Current: {report.current_workspace_id}\n\n")
                    
                    for issue in fixed_issues:
                        f.write(f"FIXED: {issue.identifier}\n")
                        f.write(f"  Significance: {issue.significance}\n")
                        f.write(f"  Impact: {issue.risk_impact}\n")
                        if issue.old_data:
                            severity = issue.old_data.get('severity', 'unknown')
                            template_name = issue.old_data.get('template_name', 'Unknown')
                            f.write(f"  Details: {template_name} ({severity})\n")
                        f.write("\n")
                logger.info(f"Saved {len(fixed_issues)} fixed issues to {fixed_file}")
            
            # 4. Save change_summary.md
            summary_file = monitoring_dir / "change_summary.md"
            summary_content = self._generate_markdown_summary(report)
            with open(summary_file, 'w') as f:
                f.write(summary_content)
            logger.info(f"Saved change summary to {summary_file}")
            
            # 5. Save all_changes.json (detailed change data)
            changes_file = monitoring_dir / "all_changes.json"
            changes_data = {
                "target": report.target,
                "baseline_workspace": report.baseline_workspace_id,
                "current_workspace": report.current_workspace_id,
                "baseline_date": report.baseline_date,
                "current_date": report.current_date,
                "risk_delta": report.risk_delta,
                "summary_stats": report.summary_stats,
                "changes": [
                    {
                        "change_type": c.change_type.value,
                        "finding_type": c.finding_type.value,
                        "identifier": c.identifier,
                        "significance": c.significance,
                        "description": c.description,
                        "risk_impact": c.risk_impact,
                        "old_data": c.old_data,
                        "new_data": c.new_data
                    }
                    for c in report.changes
                ],
                "recommendations": report.recommendations
            }
            with open(changes_file, 'w') as f:
                json.dump(changes_data, f, indent=2, default=str)
            logger.info(f"Saved detailed changes to {changes_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving change outputs: {e}")
            return False
    
    def _generate_markdown_summary(self, report: ChangeReport) -> str:
        """Generate a human-readable markdown change summary"""
        
        md = f"""# Change Detection Report

**Target:** {report.target}  
**Report Date:** {report.current_date[:16]}  
**Risk Delta:** {report.risk_delta.replace('_', ' ').title()}

## Scan Comparison

| Metric | Baseline | Current | Change |
|--------|----------|---------|--------|
| Workspace ID | {report.baseline_workspace_id} | {report.current_workspace_id} | - |
| Scan Date | {report.baseline_date[:16]} | {report.current_date[:16]} | - |
| Total Findings | {report.summary_stats.get('baseline_total', 0)} | {report.summary_stats.get('current_total', 0)} | {report.summary_stats.get('net_change', 0):+d} |

## Change Summary

"""
        
        stats = report.summary_stats
        
        # Add summary statistics
        md += f"- **Total Changes:** {stats.get('total_changes', 0)}\n"
        md += f"- **New Findings:** {stats.get('new_findings', 0)}\n"
        md += f"- **Removed Findings:** {stats.get('removed_findings', 0)}\n"
        md += f"- **Modified Findings:** {stats.get('modified_findings', 0)}\n\n"
        
        # Add findings by type
        if stats.get('new_subdomains', 0) > 0:
            md += f"🌐 **New Subdomains:** {stats['new_subdomains']}\n"
        if stats.get('new_live_hosts', 0) > 0:
            md += f"🎯 **New Live Hosts:** {stats['new_live_hosts']}\n"
        if stats.get('new_ports', 0) > 0:
            md += f"🔌 **New Ports:** {stats['new_ports']}\n"
        if stats.get('new_vulnerabilities', 0) > 0:
            md += f"🚨 **New Vulnerabilities:** {stats['new_vulnerabilities']}\n"
        
        # Add significance breakdown
        md += f"\n## Significance Breakdown\n\n"
        for sig in ["critical", "high", "medium", "low"]:
            count = stats.get(f"{sig}_significance", 0)
            if count > 0:
                emoji = {"critical": "🚨", "high": "🔥", "medium": "⚠️", "low": "ℹ️"}[sig]
                md += f"- {emoji} **{sig.title()}:** {count}\n"
        
        # Add detailed changes
        if report.changes:
            md += f"\n## Detailed Changes\n\n"
            
            # Group changes by type
            new_changes = [c for c in report.changes if c.change_type == ChangeType.NEW]
            removed_changes = [c for c in report.changes if c.change_type == ChangeType.REMOVED]
            modified_changes = [c for c in report.changes if c.change_type == ChangeType.MODIFIED]
            
            if new_changes:
                md += f"### ➕ New Findings ({len(new_changes)})\n\n"
                for change in new_changes[:10]:  # Limit to first 10
                    sig_emoji = {"critical": "🚨", "high": "🔥", "medium": "⚠️", "low": "ℹ️"}.get(change.significance, "•")
                    md += f"- {sig_emoji} **{change.finding_type.value.title()}:** {change.identifier}\n"
                    md += f"  *{change.risk_impact}*\n"
                if len(new_changes) > 10:
                    md += f"  ... and {len(new_changes) - 10} more\n"
                md += "\n"
            
            if removed_changes:
                md += f"### ➖ Removed/Fixed ({len(removed_changes)})\n\n"
                for change in removed_changes[:10]:
                    md += f"- ✅ **{change.finding_type.value.title()}:** {change.identifier}\n"
                    md += f"  *{change.risk_impact}*\n"
                if len(removed_changes) > 10:
                    md += f"  ... and {len(removed_changes) - 10} more\n"
                md += "\n"
            
            if modified_changes:
                md += f"### 🔄 Modified ({len(modified_changes)})\n\n"
                for change in modified_changes[:5]:
                    md += f"- **{change.finding_type.value.title()}:** {change.identifier}\n"
                    md += f"  *{change.risk_impact}*\n"
                if len(modified_changes) > 5:
                    md += f"  ... and {len(modified_changes) - 5} more\n"
                md += "\n"
        
        # Add recommendations
        if report.recommendations:
            md += f"## 📋 Recommendations\n\n"
            for i, rec in enumerate(report.recommendations, 1):
                if "AI:" in rec or "business impact" in rec.lower() or "strategic" in rec.lower():
                    md += f"{i}. 🤖 **AI Enhanced:** {rec}\n"
                else:
                    md += f"{i}. {rec}\n"
        
        # Add AI analysis section if available
        ai_recommendations = [r for r in report.recommendations if "AI:" in r or "business impact" in r.lower()]
        if ai_recommendations:
            md += f"\n## 🤖 AI Analysis Insights\n\n"
            md += f"*This report includes enhanced analysis powered by artificial intelligence*\n\n"
            md += f"- **AI-Enhanced Recommendations:** {len(ai_recommendations)} strategic insights provided\n"
            md += f"- **Intelligence Integration:** Change significance and risk assessment enhanced by AI analysis\n"
        
        # Add footer
        md += f"\n---\n*Report generated by BugHound Change Detection Engine*  \n"
        md += f"*Baseline: {report.baseline_workspace_id} | Current: {report.current_workspace_id}*\n"
        
        return md


# Utility functions
def format_change_report(report: ChangeReport) -> str:
    """Format a change report for human-readable display"""
    
    output = f"# Change Report: {report.target}\n\n"
    output += f"**Baseline:** {report.baseline_date[:16]} (Workspace: {report.baseline_workspace_id})\n"
    output += f"**Current:** {report.current_date[:16]} (Workspace: {report.current_workspace_id})\n"
    output += f"**Risk Delta:** {report.risk_delta.replace('_', ' ').title()}\n\n"
    
    # Summary statistics
    stats = report.summary_stats
    output += f"## Summary\n"
    output += f"- **Total Changes:** {stats['total_changes']}\n"
    output += f"- **New Findings:** {stats['new_findings']}\n"
    output += f"- **Removed Findings:** {stats['removed_findings']}\n"
    output += f"- **Modified Findings:** {stats['modified_findings']}\n"
    output += f"- **Net Change:** {stats['net_change']:+d}\n\n"
    
    # Changes by type
    if stats.get('new_subdomains', 0) > 0:
        output += f"🌐 **New Subdomains:** {stats['new_subdomains']}\n"
    if stats.get('new_live_hosts', 0) > 0:
        output += f"🎯 **New Live Hosts:** {stats['new_live_hosts']}\n"
    if stats.get('new_ports', 0) > 0:
        output += f"🔌 **New Ports:** {stats['new_ports']}\n"
    if stats.get('new_vulnerabilities', 0) > 0:
        output += f"🚨 **New Vulnerabilities:** {stats['new_vulnerabilities']}\n"
    
    # Recommendations
    if report.recommendations:
        output += f"\n## Recommendations\n"
        for rec in report.recommendations:
            output += f"- {rec}\n"
    
    return output


def format_change_list(changes: List[Change], change_type: ChangeType, max_items: int = 10) -> str:
    """Format a list of specific changes"""
    
    filtered_changes = [c for c in changes if c.change_type == change_type]
    if not filtered_changes:
        return f"No {change_type.value} findings.\n"
    
    output = f"## {change_type.value.title()} Findings ({len(filtered_changes)})\n\n"
    
    for i, change in enumerate(filtered_changes[:max_items]):
        significance_emoji = {
            "critical": "🚨",
            "high": "🔥", 
            "medium": "⚠️",
            "low": "ℹ️"
        }.get(change.significance, "•")
        
        output += f"{significance_emoji} **{change.finding_type.value.title()}:** {change.identifier}\n"
        output += f"   {change.description}\n"
        if change.risk_impact:
            output += f"   *{change.risk_impact}*\n"
        output += "\n"
    
    if len(filtered_changes) > max_items:
        output += f"... and {len(filtered_changes) - max_items} more {change_type.value} findings\n"
    
    return output