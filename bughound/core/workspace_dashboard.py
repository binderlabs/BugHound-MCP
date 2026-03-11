#!/usr/bin/env python3
"""
Workspace Dashboard System for BugHound

Generates comprehensive visual summaries of workspace data including:
- Asset discovery statistics  
- Vulnerability analysis
- Risk assessments
- Progress tracking
- Change metrics
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import re
import statistics

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Overall risk assessment levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class AssetStatistics:
    """Asset discovery statistics"""
    subdomains_discovered: int = 0
    live_hosts: int = 0
    total_ports_scanned: int = 0
    open_ports: int = 0
    unique_services: int = 0
    technologies_identified: int = 0
    urls_discovered: int = 0
    endpoints_found: int = 0


@dataclass
class VulnerabilityBreakdown:
    """Vulnerability statistics by severity"""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_vulnerabilities: int = 0
    unique_vulnerability_types: int = 0
    exploitable_count: int = 0


@dataclass
class ScanMetrics:
    """Scan performance and timing metrics"""
    scan_start_time: str = ""
    scan_duration_minutes: int = 0
    tools_executed: int = 0
    success_rate: float = 0.0
    data_points_collected: int = 0
    efficiency_score: float = 0.0
    last_updated: str = ""


@dataclass
class RiskAssessment:
    """Overall risk assessment for the target"""
    overall_risk_level: RiskLevel = RiskLevel.MINIMAL
    risk_score: float = 0.0
    attack_surface_score: float = 0.0
    vulnerability_density: float = 0.0
    exploitability_rating: str = "Low"
    business_impact: str = "Minimal"
    urgency_level: str = "Standard"


@dataclass
class TechnologyStack:
    """Technology stack analysis"""
    web_servers: List[str] = None
    programming_languages: List[str] = None
    frameworks: List[str] = None
    databases: List[str] = None
    cms_platforms: List[str] = None
    javascript_libraries: List[str] = None
    cloud_services: List[str] = None
    security_headers: Dict[str, bool] = None
    
    def __post_init__(self):
        if self.web_servers is None:
            self.web_servers = []
        if self.programming_languages is None:
            self.programming_languages = []
        if self.frameworks is None:
            self.frameworks = []
        if self.databases is None:
            self.databases = []
        if self.cms_platforms is None:
            self.cms_platforms = []
        if self.javascript_libraries is None:
            self.javascript_libraries = []
        if self.cloud_services is None:
            self.cloud_services = []
        if self.security_headers is None:
            self.security_headers = {}


@dataclass
class ChangeMetrics:
    """Change tracking metrics from previous scans"""
    has_baseline: bool = False
    new_assets_discovered: int = 0
    removed_assets: int = 0
    new_vulnerabilities: int = 0
    fixed_vulnerabilities: int = 0
    risk_delta: str = "unchanged"
    change_percentage: float = 0.0
    last_scan_date: Optional[str] = None


@dataclass
class WorkspaceSummary:
    """Complete workspace summary for fast loading"""
    workspace_id: str
    target: str
    created_date: str
    last_updated: str
    scan_status: str
    asset_stats: AssetStatistics
    vulnerability_breakdown: VulnerabilityBreakdown
    scan_metrics: ScanMetrics
    risk_assessment: RiskAssessment
    technology_stack: TechnologyStack
    change_metrics: ChangeMetrics
    ai_insights: List[str] = None
    top_recommendations: List[str] = None
    evidence_summary: Dict[str, int] = None
    
    def __post_init__(self):
        if self.ai_insights is None:
            self.ai_insights = []
        if self.top_recommendations is None:
            self.top_recommendations = []
        if self.evidence_summary is None:
            self.evidence_summary = {}


class WorkspaceDashboard:
    """Comprehensive workspace dashboard generator"""
    
    def __init__(self, workspace_manager, change_detector=None, ai_client=None):
        """
        Initialize dashboard with required components
        
        Args:
            workspace_manager: WorkspaceManager instance
            change_detector: ChangeDetector for metrics comparison
            ai_client: AI client for enhanced insights
        """
        self.workspace_manager = workspace_manager
        self.change_detector = change_detector
        self.ai_client = ai_client
        
    async def generate_dashboard(self, workspace_id: str, include_ai: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive dashboard for workspace
        
        Args:
            workspace_id: Workspace to analyze
            include_ai: Whether to include AI-generated insights
            
        Returns:
            Complete dashboard data structure
        """
        
        try:
            logger.info(f"Generating dashboard for workspace {workspace_id}")
            
            # Get workspace metadata
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                raise ValueError(f"Workspace {workspace_id} not found")
            
            # Generate workspace summary
            summary = await self._generate_workspace_summary(workspace_id, include_ai)
            
            # Generate visual representations
            visuals = await self._generate_dashboard_visuals(summary)
            
            # Create dashboard response
            dashboard = {
                "workspace_id": workspace_id,
                "target": workspace.metadata.target,
                "generated_at": datetime.now().isoformat(),
                "summary": summary,
                "visuals": visuals,
                "quick_stats": self._extract_quick_stats(summary),
                "status": "success"
            }
            
            # Save summary for fast loading
            await self._save_workspace_summary(workspace_id, summary)
            
            logger.info(f"Dashboard generated successfully for {workspace.metadata.target}")
            return dashboard
            
        except Exception as e:
            logger.error(f"Failed to generate dashboard: {e}")
            return {
                "workspace_id": workspace_id,
                "error": str(e),
                "generated_at": datetime.now().isoformat(),
                "status": "failed"
            }
    
    async def _generate_workspace_summary(self, workspace_id: str, include_ai: bool) -> WorkspaceSummary:
        """Generate complete workspace summary"""
        
        # Get workspace and results
        workspace = await self.workspace_manager.get_workspace(workspace_id)
        all_results = await self.workspace_manager.get_all_results(workspace_id)
        
        if not all_results:
            all_results = {"tools": {}, "summary_stats": {}}
        
        # Generate each summary component
        asset_stats = await self._analyze_asset_discovery(all_results)
        vuln_breakdown = await self._analyze_vulnerabilities(all_results)
        scan_metrics = await self._analyze_scan_performance(workspace, all_results)
        tech_stack = await self._analyze_technology_stack(all_results)
        change_metrics = await self._analyze_changes(workspace_id)
        risk_assessment = await self._calculate_risk_assessment(asset_stats, vuln_breakdown, tech_stack)
        
        # Get AI insights if available
        ai_insights = []
        top_recommendations = []
        if include_ai and self.ai_client and self.ai_client.is_available():
            ai_insights, top_recommendations = await self._generate_ai_insights(
                asset_stats, vuln_breakdown, risk_assessment, all_results
            )
        
        # Get evidence summary
        evidence_summary = await self._get_evidence_summary(workspace_id)
        
        return WorkspaceSummary(
            workspace_id=workspace_id,
            target=workspace.metadata.target,
            created_date=workspace.metadata.created_date,
            last_updated=datetime.now().isoformat(),
            scan_status=self._determine_scan_status(all_results),
            asset_stats=asset_stats,
            vulnerability_breakdown=vuln_breakdown,
            scan_metrics=scan_metrics,
            risk_assessment=risk_assessment,
            technology_stack=tech_stack,
            change_metrics=change_metrics,
            ai_insights=ai_insights,
            top_recommendations=top_recommendations,
            evidence_summary=evidence_summary
        )
    
    async def _analyze_asset_discovery(self, all_results: Dict[str, Any]) -> AssetStatistics:
        """Analyze asset discovery statistics"""
        
        stats = AssetStatistics()
        tools = all_results.get("tools", {})
        
        # Subdomain statistics
        if "subfinder" in tools:
            subfinder_data = tools["subfinder"].get("results", {})
            stats.subdomains_discovered = subfinder_data.get("count", 0)
        
        # Live host statistics
        if "httpx" in tools:
            httpx_data = tools["httpx"].get("results", {})
            stats.live_hosts = httpx_data.get("total_live", 0)
            
            # Technology analysis
            live_hosts = httpx_data.get("live_hosts", [])
            technologies = set()
            for host in live_hosts:
                host_techs = host.get("technologies", [])
                technologies.update(host_techs)
            stats.technologies_identified = len(technologies)
        
        # Port scan statistics
        if "nmap" in tools:
            nmap_data = tools["nmap"].get("results", {})
            hosts = nmap_data.get("hosts", [])
            total_ports = 0
            open_ports = 0
            services = set()
            
            for host in hosts:
                ports = host.get("ports", [])
                total_ports += len(ports)
                for port in ports:
                    if port.get("state") == "open":
                        open_ports += 1
                        service = port.get("service", "unknown")
                        if service != "unknown":
                            services.add(service)
            
            stats.total_ports_scanned = total_ports
            stats.open_ports = open_ports
            stats.unique_services = len(services)
        
        # URL discovery
        if "waybackurls" in tools:
            wayback_data = tools["waybackurls"].get("results", {})
            stats.urls_discovered = wayback_data.get("total_urls", 0)
            stats.endpoints_found = wayback_data.get("unique_endpoints", 0)
        
        return stats
    
    async def _analyze_vulnerabilities(self, all_results: Dict[str, Any]) -> VulnerabilityBreakdown:
        """Analyze vulnerability statistics"""
        
        breakdown = VulnerabilityBreakdown()
        tools = all_results.get("tools", {})
        
        if "nuclei" in tools:
            nuclei_data = tools["nuclei"].get("results", {})
            vulnerabilities = nuclei_data.get("vulnerabilities", [])
            
            # Count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            vulnerability_types = set()
            exploitable = 0
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                # Track unique types
                template_id = vuln.get("template_id", "unknown")
                vulnerability_types.add(template_id)
                
                # Check exploitability (simple heuristic)
                if severity in ["critical", "high"] and vuln.get("curl_command"):
                    exploitable += 1
            
            breakdown.critical_count = severity_counts["critical"]
            breakdown.high_count = severity_counts["high"]
            breakdown.medium_count = severity_counts["medium"]
            breakdown.low_count = severity_counts["low"]
            breakdown.info_count = severity_counts["info"]
            breakdown.total_vulnerabilities = len(vulnerabilities)
            breakdown.unique_vulnerability_types = len(vulnerability_types)
            breakdown.exploitable_count = exploitable
        
        return breakdown
    
    async def _analyze_scan_performance(self, workspace, all_results: Dict[str, Any]) -> ScanMetrics:
        """Analyze scan performance metrics"""
        
        metrics = ScanMetrics()
        tools = all_results.get("tools", {})
        
        # Basic timing information
        metrics.scan_start_time = workspace.metadata.created_date
        metrics.last_updated = datetime.now().isoformat()
        
        # Calculate duration (rough estimate)
        created_time = datetime.fromisoformat(workspace.metadata.created_date.replace('Z', '+00:00'))
        duration = datetime.now() - created_time.replace(tzinfo=None)
        metrics.scan_duration_minutes = int(duration.total_seconds() / 60)
        
        # Tool execution statistics
        metrics.tools_executed = len(tools)
        
        # Calculate success rate
        successful_tools = 0
        total_data_points = 0
        
        for tool_name, tool_data in tools.items():
            if tool_data.get("results"):
                successful_tools += 1
                
                # Count data points
                results = tool_data["results"]
                if tool_name == "subfinder":
                    total_data_points += results.get("count", 0)
                elif tool_name == "httpx":
                    total_data_points += results.get("total_live", 0)
                elif tool_name == "nuclei":
                    total_data_points += len(results.get("vulnerabilities", []))
                elif tool_name == "nmap":
                    hosts = results.get("hosts", [])
                    for host in hosts:
                        total_data_points += len(host.get("ports", []))
        
        metrics.success_rate = (successful_tools / max(len(tools), 1)) * 100
        metrics.data_points_collected = total_data_points
        
        # Calculate efficiency score (data points per minute)
        if metrics.scan_duration_minutes > 0:
            metrics.efficiency_score = total_data_points / metrics.scan_duration_minutes
        
        return metrics
    
    async def _analyze_technology_stack(self, all_results: Dict[str, Any]) -> TechnologyStack:
        """Analyze discovered technology stack"""
        
        tech_stack = TechnologyStack()
        tools = all_results.get("tools", {})
        
        if "httpx" in tools:
            httpx_data = tools["httpx"].get("results", {})
            live_hosts = httpx_data.get("live_hosts", [])
            
            web_servers = set()
            technologies = set()
            
            for host in live_hosts:
                # Server headers
                server = host.get("server", "")
                if server:
                    # Extract server type
                    server_name = server.split("/")[0].lower()
                    web_servers.add(server_name)
                
                # Technologies
                host_techs = host.get("technologies", [])
                technologies.update(host_techs)
            
            tech_stack.web_servers = list(web_servers)
            
            # Categorize technologies
            for tech in technologies:
                tech_lower = tech.lower()
                
                # Programming languages
                if any(lang in tech_lower for lang in ["php", "python", "java", "node", "ruby", "asp"]):
                    tech_stack.programming_languages.append(tech)
                
                # Frameworks
                elif any(fw in tech_lower for fw in ["django", "rails", "express", "spring", "laravel"]):
                    tech_stack.frameworks.append(tech)
                
                # Databases
                elif any(db in tech_lower for db in ["mysql", "postgres", "mongodb", "redis", "sqlite"]):
                    tech_stack.databases.append(tech)
                
                # CMS
                elif any(cms in tech_lower for cms in ["wordpress", "drupal", "joomla", "magento"]):
                    tech_stack.cms_platforms.append(tech)
                
                # JavaScript libraries
                elif any(js in tech_lower for js in ["jquery", "react", "vue", "angular", "bootstrap"]):
                    tech_stack.javascript_libraries.append(tech)
                
                # Cloud services
                elif any(cloud in tech_lower for cloud in ["aws", "azure", "gcp", "cloudflare"]):
                    tech_stack.cloud_services.append(tech)
        
        return tech_stack
    
    async def _analyze_changes(self, workspace_id: str) -> ChangeMetrics:
        """Analyze changes from previous scans"""
        
        change_metrics = ChangeMetrics()
        
        if self.change_detector:
            try:
                # Find previous workspaces for the same target
                workspace = await self.workspace_manager.get_workspace(workspace_id)
                if workspace:
                    target = workspace.metadata.target
                    previous_workspaces = await self.workspace_manager.search_workspaces(target)
                    
                    # Find baseline workspace
                    baseline_workspace = None
                    for ws in previous_workspaces:
                        if ws.metadata.workspace_id != workspace_id:
                            baseline_workspace = ws
                            break
                    
                    if baseline_workspace:
                        change_metrics.has_baseline = True
                        change_metrics.last_scan_date = baseline_workspace.metadata.created_date
                        
                        # Run change detection
                        change_report = await self.change_detector.compare_workspaces(
                            baseline_workspace.metadata.workspace_id,
                            workspace_id
                        )
                        
                        if change_report:
                            change_metrics.risk_delta = change_report.risk_delta
                            
                            # Calculate change statistics
                            new_changes = len([c for c in change_report.changes if c.change_type.value == "new"])
                            removed_changes = len([c for c in change_report.changes if c.change_type.value == "removed"])
                            
                            change_metrics.new_assets_discovered = new_changes
                            change_metrics.removed_assets = removed_changes
                            
                            # Calculate change percentage
                            total_changes = len(change_report.changes)
                            if total_changes > 0:
                                change_metrics.change_percentage = (new_changes / total_changes) * 100
                    
            except Exception as e:
                logger.warning(f"Failed to analyze changes: {e}")
        
        return change_metrics
    
    async def _calculate_risk_assessment(
        self, 
        asset_stats: AssetStatistics, 
        vuln_breakdown: VulnerabilityBreakdown,
        tech_stack: TechnologyStack
    ) -> RiskAssessment:
        """Calculate overall risk assessment"""
        
        assessment = RiskAssessment()
        
        # Calculate risk score (0-10 scale)
        risk_score = 0.0
        
        # Vulnerability-based risk
        vuln_risk = 0.0
        vuln_risk += vuln_breakdown.critical_count * 4.0
        vuln_risk += vuln_breakdown.high_count * 2.5
        vuln_risk += vuln_breakdown.medium_count * 1.0
        vuln_risk += vuln_breakdown.low_count * 0.3
        
        # Attack surface risk
        surface_risk = 0.0
        surface_risk += min(asset_stats.live_hosts * 0.1, 2.0)
        surface_risk += min(asset_stats.open_ports * 0.05, 1.5)
        surface_risk += min(asset_stats.unique_services * 0.1, 1.0)
        
        # Technology risk (outdated or risky technologies)
        tech_risk = 0.0
        risky_techs = ["apache", "iis", "php", "wordpress", "joomla"]
        for tech_list in [tech_stack.web_servers, tech_stack.cms_platforms, tech_stack.programming_languages]:
            for tech in tech_list:
                if any(risky in tech.lower() for risky in risky_techs):
                    tech_risk += 0.2
        
        risk_score = min(vuln_risk + surface_risk + tech_risk, 10.0)
        assessment.risk_score = round(risk_score, 1)
        assessment.attack_surface_score = round(surface_risk, 1)
        
        # Determine overall risk level
        if risk_score >= 8.0:
            assessment.overall_risk_level = RiskLevel.CRITICAL
            assessment.urgency_level = "Immediate"
            assessment.business_impact = "Severe"
        elif risk_score >= 6.0:
            assessment.overall_risk_level = RiskLevel.HIGH
            assessment.urgency_level = "High"
            assessment.business_impact = "Significant"
        elif risk_score >= 4.0:
            assessment.overall_risk_level = RiskLevel.MEDIUM
            assessment.urgency_level = "Medium"
            assessment.business_impact = "Moderate"
        elif risk_score >= 2.0:
            assessment.overall_risk_level = RiskLevel.LOW
            assessment.urgency_level = "Low"
            assessment.business_impact = "Minor"
        else:
            assessment.overall_risk_level = RiskLevel.MINIMAL
            assessment.urgency_level = "Standard"
            assessment.business_impact = "Minimal"
        
        # Calculate vulnerability density
        if asset_stats.live_hosts > 0:
            assessment.vulnerability_density = vuln_breakdown.total_vulnerabilities / asset_stats.live_hosts
        
        # Determine exploitability
        if vuln_breakdown.exploitable_count > 0:
            if vuln_breakdown.critical_count > 0:
                assessment.exploitability_rating = "Critical"
            elif vuln_breakdown.high_count > 0:
                assessment.exploitability_rating = "High"
            else:
                assessment.exploitability_rating = "Medium"
        else:
            assessment.exploitability_rating = "Low"
        
        return assessment
    
    async def _generate_ai_insights(
        self, 
        asset_stats: AssetStatistics,
        vuln_breakdown: VulnerabilityBreakdown,
        risk_assessment: RiskAssessment,
        all_results: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        """Generate AI-powered insights and recommendations"""
        
        try:
            # Prepare data for AI analysis
            context_data = {
                "assets": asdict(asset_stats),
                "vulnerabilities": asdict(vuln_breakdown),
                "risk": asdict(risk_assessment),
                "scan_summary": all_results.get("summary_stats", {})
            }
            
            # Generate AI insights
            prompt = self._build_dashboard_ai_prompt(context_data)
            response = await self.ai_client.complete(prompt)
            
            # Parse AI response
            insights, recommendations = self._parse_ai_dashboard_response(response)
            
            return insights, recommendations
            
        except Exception as e:
            logger.warning(f"Failed to generate AI insights: {e}")
            return [], []
    
    def _build_dashboard_ai_prompt(self, data: Dict[str, Any]) -> str:
        """Build AI prompt for dashboard insights"""
        
        return f"""
Analyze this security reconnaissance data and provide strategic insights:

ASSET DISCOVERY:
- Subdomains: {data['assets']['subdomains_discovered']}
- Live Hosts: {data['assets']['live_hosts']}
- Open Ports: {data['assets']['open_ports']}
- Services: {data['assets']['unique_services']}
- Technologies: {data['assets']['technologies_identified']}

VULNERABILITIES:
- Critical: {data['vulnerabilities']['critical_count']}
- High: {data['vulnerabilities']['high_count']}
- Medium: {data['vulnerabilities']['medium_count']}
- Low: {data['vulnerabilities']['low_count']}
- Total: {data['vulnerabilities']['total_vulnerabilities']}

RISK ASSESSMENT:
- Overall Risk: {data['risk']['overall_risk_level']}
- Risk Score: {data['risk']['risk_score']}/10
- Attack Surface: {data['risk']['attack_surface_score']}

Provide:
1. 3-5 key strategic insights about the security posture
2. 3-5 prioritized recommendations for immediate action

Format as:
INSIGHTS:
- [insight 1]
- [insight 2]
- [insight 3]

RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]
- [recommendation 3]
"""
    
    def _parse_ai_dashboard_response(self, response: str) -> Tuple[List[str], List[str]]:
        """Parse AI response into insights and recommendations"""
        
        insights = []
        recommendations = []
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'INSIGHTS:' in line.upper():
                current_section = 'insights'
                continue
            elif 'RECOMMENDATIONS:' in line.upper():
                current_section = 'recommendations'
                continue
            
            if line.startswith('- ') or line.startswith('• '):
                content = line[2:].strip()
                if current_section == 'insights':
                    insights.append(content)
                elif current_section == 'recommendations':
                    recommendations.append(content)
        
        return insights[:5], recommendations[:5]  # Limit to 5 each
    
    async def _get_evidence_summary(self, workspace_id: str) -> Dict[str, int]:
        """Get evidence collection summary"""
        
        try:
            # Try to get evidence collector
            from .evidence_collector import EvidenceCollector
            evidence_collector = EvidenceCollector(self.workspace_manager)
            
            evidence_summary = await evidence_collector.list_evidence_for_workspace(workspace_id)
            
            return {
                "total_evidence": evidence_summary.get("evidence_count", 0),
                "findings_with_evidence": evidence_summary.get("finding_count", 0)
            }
            
        except Exception as e:
            logger.debug(f"Evidence summary not available: {e}")
            return {"total_evidence": 0, "findings_with_evidence": 0}
    
    def _determine_scan_status(self, all_results: Dict[str, Any]) -> str:
        """Determine current scan status"""
        
        tools = all_results.get("tools", {})
        
        if not tools:
            return "No data"
        
        # Check if basic tools have run
        basic_tools = ["subfinder", "httpx"]
        basic_complete = all(tool in tools for tool in basic_tools)
        
        # Check if advanced tools have run
        advanced_tools = ["nuclei", "nmap"]
        advanced_complete = any(tool in tools for tool in advanced_tools)
        
        if basic_complete and advanced_complete:
            return "Complete"
        elif basic_complete:
            return "Partial"
        else:
            return "In Progress"
    
    async def _generate_dashboard_visuals(self, summary: WorkspaceSummary) -> Dict[str, str]:
        """Generate ASCII visual representations"""
        
        visuals = {}
        
        # Risk score visualization
        visuals["risk_gauge"] = self._create_risk_gauge(summary.risk_assessment.risk_score)
        
        # Vulnerability distribution chart
        visuals["vulnerability_chart"] = self._create_vulnerability_chart(summary.vulnerability_breakdown)
        
        # Asset discovery progress
        visuals["asset_progress"] = self._create_asset_progress(summary.asset_stats)
        
        # Technology stack summary
        visuals["technology_summary"] = self._create_technology_visual(summary.technology_stack)
        
        # Scan efficiency meter
        visuals["efficiency_meter"] = self._create_efficiency_meter(summary.scan_metrics)
        
        return visuals
    
    def _create_risk_gauge(self, risk_score: float) -> str:
        """Create ASCII risk gauge visualization"""
        
        gauge_width = 40
        filled_width = int((risk_score / 10.0) * gauge_width)
        
        # Color coding based on risk level
        if risk_score >= 8.0:
            risk_label = "CRITICAL"
            marker = "█"
        elif risk_score >= 6.0:
            risk_label = "HIGH"
            marker = "▓"
        elif risk_score >= 4.0:
            risk_label = "MEDIUM" 
            marker = "▒"
        else:
            risk_label = "LOW"
            marker = "░"
        
        gauge = f"""
╭─── Risk Score: {risk_score}/10 ({risk_label}) ───╮
│ {"█" * filled_width}{"░" * (gauge_width - filled_width)} │
│ 0    2    4    6    8    10 │
╰{"─" * (gauge_width + 6)}╯
"""
        return gauge.strip()
    
    def _create_vulnerability_chart(self, vuln_breakdown: VulnerabilityBreakdown) -> str:
        """Create ASCII vulnerability distribution chart"""
        
        if vuln_breakdown.total_vulnerabilities == 0:
            return "No vulnerabilities found"
        
        # Calculate percentages and bar lengths
        total = vuln_breakdown.total_vulnerabilities
        max_bar_width = 30
        
        critical_width = int((vuln_breakdown.critical_count / total) * max_bar_width) if total > 0 else 0
        high_width = int((vuln_breakdown.high_count / total) * max_bar_width) if total > 0 else 0
        medium_width = int((vuln_breakdown.medium_count / total) * max_bar_width) if total > 0 else 0
        low_width = int((vuln_breakdown.low_count / total) * max_bar_width) if total > 0 else 0
        
        chart = f"""
Vulnerability Distribution (Total: {total})
╭─────────────────────────────────────────╮
│ Critical │{"█" * critical_width:<30}│ {vuln_breakdown.critical_count:>3}
│ High     │{"▓" * high_width:<30}│ {vuln_breakdown.high_count:>3}
│ Medium   │{"▒" * medium_width:<30}│ {vuln_breakdown.medium_count:>3}
│ Low      │{"░" * low_width:<30}│ {vuln_breakdown.low_count:>3}
╰─────────────────────────────────────────╯
"""
        return chart.strip()
    
    def _create_asset_progress(self, asset_stats: AssetStatistics) -> str:
        """Create asset discovery progress visualization"""
        
        progress = f"""
Asset Discovery Summary
╭─────────────────────────────────╮
│ Subdomains    │ {asset_stats.subdomains_discovered:>8} found │
│ Live Hosts    │ {asset_stats.live_hosts:>8} active│
│ Open Ports    │ {asset_stats.open_ports:>8} open  │
│ Services      │ {asset_stats.unique_services:>8} unique│
│ Technologies  │ {asset_stats.technologies_identified:>8} found │
╰─────────────────────────────────╯
"""
        return progress.strip()
    
    def _create_technology_visual(self, tech_stack: TechnologyStack) -> str:
        """Create technology stack visualization"""
        
        tech_summary = f"""
Technology Stack Identified
╭─────────────────────────────────╮
│ Web Servers   │ {len(tech_stack.web_servers):>3} detected   │
│ Languages     │ {len(tech_stack.programming_languages):>3} identified│
│ Frameworks    │ {len(tech_stack.frameworks):>3} found      │
│ CMS/Platforms │ {len(tech_stack.cms_platforms):>3} discovered │
│ JS Libraries  │ {len(tech_stack.javascript_libraries):>3} found      │
╰─────────────────────────────────╯
"""
        return tech_summary.strip()
    
    def _create_efficiency_meter(self, scan_metrics: ScanMetrics) -> str:
        """Create scan efficiency visualization"""
        
        efficiency = f"""
Scan Performance Metrics
╭─────────────────────────────────╮
│ Duration      │ {scan_metrics.scan_duration_minutes:>8} mins │
│ Tools Used    │ {scan_metrics.tools_executed:>8} total│
│ Success Rate  │ {scan_metrics.success_rate:>7.1f}%    │
│ Data Points   │ {scan_metrics.data_points_collected:>8} items│
│ Efficiency    │ {scan_metrics.efficiency_score:>7.1f}/min  │
╰─────────────────────────────────╯
"""
        return efficiency.strip()
    
    def _extract_quick_stats(self, summary: WorkspaceSummary) -> Dict[str, Any]:
        """Extract quick stats for fast loading"""
        
        return {
            "target": summary.target,
            "risk_level": summary.risk_assessment.overall_risk_level.value,
            "risk_score": summary.risk_assessment.risk_score,
            "total_vulnerabilities": summary.vulnerability_breakdown.total_vulnerabilities,
            "critical_vulns": summary.vulnerability_breakdown.critical_count,
            "live_hosts": summary.asset_stats.live_hosts,
            "subdomains": summary.asset_stats.subdomains_discovered,
            "scan_status": summary.scan_status,
            "has_evidence": summary.evidence_summary.get("total_evidence", 0) > 0,
            "last_updated": summary.last_updated
        }
    
    async def _save_workspace_summary(self, workspace_id: str, summary: WorkspaceSummary):
        """Save workspace summary for fast loading"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if workspace:
                summary_path = workspace.workspace_path / "summary.json"
                
                # Convert summary to dict for JSON serialization
                summary_dict = asdict(summary)
                
                with open(summary_path, 'w', encoding='utf-8') as f:
                    json.dump(summary_dict, f, indent=2, ensure_ascii=False, default=str)
                
                logger.debug(f"Workspace summary saved: {summary_path}")
                
        except Exception as e:
            logger.warning(f"Failed to save workspace summary: {e}")
    
    async def load_workspace_summary(self, workspace_id: str) -> Optional[WorkspaceSummary]:
        """Load cached workspace summary"""
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if workspace:
                summary_path = workspace.workspace_path / "summary.json"
                
                if summary_path.exists():
                    with open(summary_path, 'r', encoding='utf-8') as f:
                        summary_dict = json.load(f)
                    
                    # Convert back to dataclass instances
                    summary = self._dict_to_workspace_summary(summary_dict)
                    return summary
                    
        except Exception as e:
            logger.warning(f"Failed to load workspace summary: {e}")
        
        return None
    
    def _dict_to_workspace_summary(self, data: Dict[str, Any]) -> WorkspaceSummary:
        """Convert dictionary back to WorkspaceSummary dataclass"""
        
        # Convert nested dictionaries back to dataclasses
        asset_stats = AssetStatistics(**data["asset_stats"])
        vuln_breakdown = VulnerabilityBreakdown(**data["vulnerability_breakdown"])
        scan_metrics = ScanMetrics(**data["scan_metrics"])
        
        # Handle risk assessment with enum
        risk_data = data["risk_assessment"].copy()
        risk_level_str = risk_data["overall_risk_level"]
        # Handle both enum values and string representations
        if isinstance(risk_level_str, str):
            if risk_level_str.startswith("RiskLevel."):
                risk_level_str = risk_level_str.split(".")[-1].lower()
            risk_data["overall_risk_level"] = RiskLevel(risk_level_str.lower())
        else:
            risk_data["overall_risk_level"] = RiskLevel(risk_level_str)
        risk_assessment = RiskAssessment(**risk_data)
        
        tech_stack = TechnologyStack(**data["technology_stack"])
        change_metrics = ChangeMetrics(**data["change_metrics"])
        
        return WorkspaceSummary(
            workspace_id=data["workspace_id"],
            target=data["target"],
            created_date=data["created_date"],
            last_updated=data["last_updated"],
            scan_status=data["scan_status"],
            asset_stats=asset_stats,
            vulnerability_breakdown=vuln_breakdown,
            scan_metrics=scan_metrics,
            risk_assessment=risk_assessment,
            technology_stack=tech_stack,
            change_metrics=change_metrics,
            ai_insights=data.get("ai_insights", []),
            top_recommendations=data.get("top_recommendations", []),
            evidence_summary=data.get("evidence_summary", {})
        )