"""
Pattern-Based Reconnaissance Analyzer for BugHound

Provides intelligent pattern-based analysis of reconnaissance data.
Focuses on security insights, pattern recognition, and actionable recommendations
WITHOUT external AI API calls - designed for MCP architecture.

Claude Desktop (MCP client) will handle the AI interpretation layer.
"""

import asyncio
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import json

logger = logging.getLogger(__name__)


@dataclass
class AttackSurfaceAnalysis:
    """Attack surface analysis results"""
    high_value_targets: List[str]
    security_risks: List[str]
    suspicious_patterns: List[str]
    confidence: float


@dataclass
class TechnologyInsights:
    """Technology stack insights"""
    stack_summary: str
    vulnerabilities: List[str]
    attack_vectors: List[str]
    testing_tools: List[str]


@dataclass
class NamingPatternAnalysis:
    """Subdomain naming pattern analysis"""
    conventions: List[str]
    predicted_subdomains: List[str]
    internal_schemes: List[str]
    anomalies: List[str]


@dataclass
class SecurityRecommendation:
    """Security testing recommendation"""
    priority: str  # high, medium, low
    target: str
    action: str
    tools: List[str]
    rationale: str
    estimated_time: str = "Unknown"


@dataclass
class LiveHostAnalysis:
    """Live host analysis results"""
    high_value_targets: List[Dict[str, Any]]
    admin_interfaces: List[Dict[str, Any]]
    development_environments: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    security_findings: List[str]
    infrastructure_issues: List[str]


@dataclass
class TargetPriority:
    """Target prioritization data"""
    subdomain: str
    priority_score: float
    vulnerability_potential: str
    attack_vectors: List[str]
    difficulty: str
    reasoning: str
    estimated_time: str


@dataclass
class ComprehensiveAnalysis:
    """Complete pattern-based analysis results"""
    target: str
    timestamp: datetime
    attack_surface: AttackSurfaceAnalysis
    technology_insights: TechnologyInsights
    naming_patterns: NamingPatternAnalysis
    live_host_analysis: LiveHostAnalysis
    target_priorities: List[TargetPriority]
    application_type: str
    business_context: str
    recommendations: List[SecurityRecommendation]
    overall_confidence: float
    analysis_summary: str
    next_steps: List[str]


class PatternAnalyzer:
    """
    Pattern-based analyzer for reconnaissance data

    Provides intelligent analysis of subdomains, technologies, and live hosts
    to generate actionable security testing insights using pattern matching and heuristics.

    No external AI API calls - designed for MCP architecture where Claude Desktop
    handles the AI interpretation layer.
    """

    def __init__(self):
        """Initialize pattern analyzer"""
        self.analysis_history = []

        # Pattern databases for local analysis
        self.security_patterns = self._load_security_patterns()
        self.technology_signatures = self._load_technology_signatures()

    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security-focused subdomain patterns"""
        return {
            "admin_panels": [
                r"admin", r"administration", r"panel", r"dashboard",
                r"manage", r"control", r"cms", r"wp-admin"
            ],
            "development": [
                r"dev", r"develop", r"staging", r"stage", r"test",
                r"uat", r"qa", r"beta", r"alpha", r"preview"
            ],
            "api_endpoints": [
                r"api", r"rest", r"graphql", r"webhook", r"service",
                r"microservice", r"endpoint", r"gateway"
            ],
            "internal_services": [
                r"internal", r"intranet", r"vpn", r"private",
                r"corp", r"employee", r"staff", r"hr"
            ],
            "backup_systems": [
                r"backup", r"bak", r"archive", r"old", r"legacy",
                r"deprecated", r"temp", r"tmp"
            ],
            "monitoring": [
                r"monitor", r"metrics", r"analytics", r"stats",
                r"logs", r"kibana", r"grafana", r"prometheus"
            ]
        }

    def _load_technology_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load technology vulnerability signatures"""
        return {
            "wordpress": {
                "common_vulns": ["plugin vulnerabilities", "theme vulnerabilities", "wp-admin bruteforce"],
                "testing_tools": ["wpscan", "nuclei", "burp"],
                "attack_vectors": ["plugin enumeration", "user enumeration", "xmlrpc attacks"]
            },
            "apache": {
                "common_vulns": ["server-status exposure", "directory traversal", "mod_rewrite issues"],
                "testing_tools": ["nikto", "dirb", "gobuster"],
                "attack_vectors": ["status page access", "config file exposure", "cgi-bin testing"]
            },
            "nginx": {
                "common_vulns": ["alias traversal", "off-by-slash", "proxy misconfigurations"],
                "testing_tools": ["nginx-ultimate-bad-bot-blocker", "nikto"],
                "attack_vectors": ["alias testing", "proxy bypass", "rate limit bypass"]
            },
            "cloudflare": {
                "common_vulns": ["origin server discovery", "cache poisoning", "WAF bypass"],
                "testing_tools": ["cloudflair", "censys", "shodan"],
                "attack_vectors": ["direct IP access", "subdomain takeover", "cache deception"]
            },
            "jenkins": {
                "common_vulns": ["unauthenticated access", "script console access", "credential exposure"],
                "testing_tools": ["nuclei", "burp", "metasploit"],
                "attack_vectors": ["script console exploitation", "build manipulation", "credential theft"]
            },
            "docker": {
                "common_vulns": ["exposed docker API", "container escape", "registry exposure"],
                "testing_tools": ["docker-bench", "trivy", "nuclei"],
                "attack_vectors": ["API exploitation", "registry enumeration", "container breakout"]
            }
        }

    async def analyze_live_hosts(
        self,
        live_hosts: List[Dict],
        target: str
    ) -> LiveHostAnalysis:
        """
        Analyze HTTPx live host results for interesting patterns and security issues

        Args:
            live_hosts: HTTPx scan results
            target: Target domain

        Returns:
            LiveHostAnalysis with categorized hosts and findings
        """

        if not live_hosts:
            return LiveHostAnalysis(
                high_value_targets=[],
                admin_interfaces=[],
                development_environments=[],
                api_endpoints=[],
                security_findings=[],
                infrastructure_issues=[]
            )

        # Pattern-based analysis
        high_value = []
        admin_interfaces = []
        dev_environments = []
        api_endpoints = []
        security_findings = []
        infrastructure_issues = []

        for host in live_hosts:
            url = host.get("url", "")
            title = host.get("title", "").lower()
            status = host.get("status_code", 0)
            server = host.get("server", "").lower()

            # Categorize by URL patterns
            if any(pattern in url.lower() for pattern in ["admin", "manage", "control"]):
                admin_interfaces.append({
                    "url": url,
                    "access_level": "unknown",
                    "risk_level": "high",
                    "notes": f"Admin interface detected - Status: {status}"
                })
                high_value.append({
                    "url": url,
                    "type": "Admin interface",
                    "security_score": 9.0,
                    "notes": "Administrative interface with potential privilege escalation"
                })

            elif any(pattern in url.lower() for pattern in ["api", "rest", "graphql"]):
                api_endpoints.append({
                    "url": url,
                    "api_type": "REST" if "rest" in url.lower() else "Unknown",
                    "authentication": "unknown",
                    "documentation_exposed": "swagger" in title or "api" in title
                })
                high_value.append({
                    "url": url,
                    "type": "API endpoint",
                    "security_score": 8.5,
                    "notes": "API endpoint with potential for injection and auth bypass"
                })

            elif any(pattern in url.lower() for pattern in ["dev", "test", "staging", "qa"]):
                dev_environments.append({
                    "url": url,
                    "exposure_level": "high" if status == 200 else "medium",
                    "risk_factors": ["Development environment", "Potentially less secure"]
                })

            # Check for security issues
            if status in [403, 401]:
                security_findings.append(f"Authentication required on {url} - potential bypass target")
            elif status == 500:
                security_findings.append(f"Server error on {url} - potential information disclosure")
            elif "debug" in title or "error" in title:
                security_findings.append(f"Debug/error information exposed on {url}")

            # Infrastructure analysis
            if not server:
                infrastructure_issues.append(f"Server header not disclosed on {url}")
            elif "nginx" in server and "apache" in server:
                infrastructure_issues.append(f"Multiple server technologies detected on {url}")

        return LiveHostAnalysis(
            high_value_targets=high_value,
            admin_interfaces=admin_interfaces,
            development_environments=dev_environments,
            api_endpoints=api_endpoints,
            security_findings=security_findings,
            infrastructure_issues=infrastructure_issues
        )

    async def prioritize_targets(
        self,
        subdomains: List[Any],
        live_hosts: List[Dict] = None,
        technologies: List[str] = None
    ) -> List[TargetPriority]:
        """
        Score each subdomain by bug bounty potential using pattern analysis

        Args:
            subdomains: List of discovered subdomains
            live_hosts: Live host data from httpx
            technologies: Detected technologies

        Returns:
            List of TargetPriority objects sorted by score
        """

        # Extract subdomain strings
        subdomain_list = []
        for sub in subdomains:
            if hasattr(sub, 'domain'):
                subdomain_list.append(sub.domain)
            elif isinstance(sub, str):
                subdomain_list.append(sub)
            elif isinstance(sub, dict) and 'domain' in sub:
                subdomain_list.append(sub['domain'])

        priorities = []

        # Pattern-based prioritization
        for subdomain in subdomain_list:
            score = 5.0  # Base score
            attack_vectors = ["Standard web application testing"]
            difficulty = "medium"
            reasoning = "Standard web application"
            estimated_time = "2-4 hours"
            vulnerability_potential = "Standard web vulnerabilities"

            # Pattern-based scoring
            subdomain_lower = subdomain.lower()

            if any(pattern in subdomain_lower for pattern in ["admin", "manage", "control"]):
                score = 9.5
                attack_vectors = ["Authentication bypass", "Privilege escalation", "Default credentials"]
                difficulty = "medium"
                reasoning = "Administrative interface with high privilege access"
                vulnerability_potential = "Authentication bypass, privilege escalation, sensitive data access"
                estimated_time = "4-6 hours"

            elif any(pattern in subdomain_lower for pattern in ["api", "rest", "graphql"]):
                score = 9.0
                attack_vectors = ["API parameter fuzzing", "Authentication testing", "Rate limit bypass"]
                difficulty = "medium"
                reasoning = "API endpoints often have business logic flaws and authentication issues"
                vulnerability_potential = "IDOR, authentication bypass, rate limiting issues, injection"
                estimated_time = "6-8 hours"

            elif any(pattern in subdomain_lower for pattern in ["dev", "test", "staging"]):
                score = 8.5
                attack_vectors = ["Configuration review", "Debug information", "Test data access"]
                difficulty = "low"
                reasoning = "Development environments often have weaker security controls"
                vulnerability_potential = "Debug information disclosure, test data access, weak authentication"
                estimated_time = "2-3 hours"

            elif any(pattern in subdomain_lower for pattern in ["internal", "corp", "intranet"]):
                score = 8.0
                attack_vectors = ["Internal system access", "Network reconnaissance", "Privilege escalation"]
                difficulty = "high"
                reasoning = "Internal systems may have different security models"
                vulnerability_potential = "Internal system access, network traversal, data exfiltration"
                estimated_time = "8-12 hours"

            elif any(pattern in subdomain_lower for pattern in ["mail", "email", "smtp"]):
                score = 7.0
                attack_vectors = ["Email injection", "SMTP enumeration", "Mail server exploits"]
                difficulty = "medium"
                reasoning = "Mail servers can provide user enumeration and injection opportunities"
                vulnerability_potential = "Email injection, user enumeration, mail relay abuse"
                estimated_time = "3-5 hours"

            # Boost score if host is live
            if live_hosts:
                live_urls = [host.get("url", "") for host in live_hosts]
                if any(subdomain in url for url in live_urls):
                    score += 1.0
                    reasoning += " (confirmed live host)"

            priorities.append(TargetPriority(
                subdomain=subdomain,
                priority_score=score,
                vulnerability_potential=vulnerability_potential,
                attack_vectors=attack_vectors,
                difficulty=difficulty,
                reasoning=reasoning,
                estimated_time=estimated_time
            ))

        # Sort by priority score (highest first)
        priorities.sort(key=lambda x: x.priority_score, reverse=True)

        return priorities

    async def detect_environment_type(
        self,
        subdomains: List[str],
        live_hosts: List[Dict] = None
    ) -> Dict[str, List[str]]:
        """
        Identify development, staging, and production environments

        Args:
            subdomains: List of subdomain strings
            live_hosts: Live host data for additional context

        Returns:
            Dictionary categorizing environments
        """

        environments = {
            "production": [],
            "development": [],
            "staging": [],
            "testing": [],
            "internal": [],
            "unknown": []
        }

        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()

            # Development patterns
            if any(pattern in subdomain_lower for pattern in ["dev", "develop", "devel"]):
                environments["development"].append(subdomain)
            # Staging patterns
            elif any(pattern in subdomain_lower for pattern in ["staging", "stage", "stg"]):
                environments["staging"].append(subdomain)
            # Testing patterns
            elif any(pattern in subdomain_lower for pattern in ["test", "testing", "qa", "uat", "beta"]):
                environments["testing"].append(subdomain)
            # Internal patterns
            elif any(pattern in subdomain_lower for pattern in ["internal", "corp", "intranet", "admin"]):
                environments["internal"].append(subdomain)
            # Production indicators (www, app, main service)
            elif any(pattern in subdomain_lower for pattern in ["www", "app", "api", "mail"]) or subdomain_lower.count('.') == 1:
                environments["production"].append(subdomain)
            else:
                environments["unknown"].append(subdomain)

        return environments

    async def analyze_recon_results(
        self,
        target: str,
        subdomains: List[Any],
        live_hosts: List[Dict] = None,
        technologies: List[str] = None
    ) -> ComprehensiveAnalysis:
        """
        Perform comprehensive pattern-based analysis of reconnaissance results

        Args:
            target: Target domain
            subdomains: List of discovered subdomains
            live_hosts: Live host data from httpx
            technologies: Detected technologies

        Returns:
            ComprehensiveAnalysis with all insights
        """

        logger.info(f"Starting comprehensive pattern analysis for {target}")

        # Extract subdomain strings for analysis
        subdomain_list = []
        for sub in subdomains:
            if hasattr(sub, 'domain'):
                subdomain_list.append(sub.domain)
            elif isinstance(sub, str):
                subdomain_list.append(sub)
            elif isinstance(sub, dict) and 'domain' in sub:
                subdomain_list.append(sub['domain'])

        # Perform pattern analysis
        attack_surface = await self._analyze_attack_surface(subdomain_list, live_hosts)
        technology_insights = await self._analyze_technology_stack(technologies or [], live_hosts)
        naming_patterns = await self._analyze_naming_patterns(subdomain_list, target)

        # Enhanced pattern-based analysis
        live_host_analysis = await self.analyze_live_hosts(live_hosts or [], target)
        target_priorities = await self.prioritize_targets(subdomains, live_hosts, technologies)
        environment_types = await self.detect_environment_type(subdomain_list, live_hosts)

        # Determine application type and business context (pattern-based)
        application_type = self._detect_application_type(subdomain_list, technologies or [])
        business_context = self._infer_business_context(subdomain_list, target)

        # Generate recommendations
        recommendations = self._generate_local_recommendations(
            attack_surface, technology_insights, naming_patterns
        )

        # Generate next steps
        next_steps = self._generate_next_steps(
            len(subdomain_list), len(live_hosts) if live_hosts else 0,
            len(technologies) if technologies else 0
        )

        # Analysis summary
        analysis_summary = f"Pattern-based analysis completed: {len(subdomain_list)} subdomains, {len(live_hosts) if live_hosts else 0} live hosts, {len(target_priorities)} targets prioritized"

        # Create comprehensive analysis
        analysis = ComprehensiveAnalysis(
            target=target,
            timestamp=datetime.now(),
            attack_surface=attack_surface,
            technology_insights=technology_insights,
            naming_patterns=naming_patterns,
            live_host_analysis=live_host_analysis,
            target_priorities=target_priorities,
            application_type=application_type,
            business_context=business_context,
            recommendations=recommendations,
            overall_confidence=0.85,  # Pattern-based confidence
            analysis_summary=analysis_summary,
            next_steps=next_steps
        )

        self.analysis_history.append(analysis)
        logger.info(f"Pattern analysis completed for {target}")

        return analysis

    def _detect_application_type(self, subdomains: List[str], technologies: List[str]) -> str:
        """Detect application type based on patterns"""
        subdomain_str = " ".join(subdomains).lower()
        tech_str = " ".join(technologies).lower()

        if any(word in subdomain_str for word in ["shop", "store", "cart", "payment"]):
            return "E-commerce Platform"
        elif any(word in subdomain_str for word in ["api", "microservice", "service"]):
            return "API/Microservices Platform"
        elif any(word in subdomain_str for word in ["blog", "cms", "wp"]):
            return "Content Management System"
        elif any(word in subdomain_str for word in ["mail", "smtp", "imap"]):
            return "Email/Communication Platform"
        elif "jenkins" in tech_str or "gitlab" in tech_str or "ci" in subdomain_str:
            return "Development/CI-CD Platform"
        else:
            return "Web Application"

    def _infer_business_context(self, subdomains: List[str], target: str) -> str:
        """Infer business context from patterns"""
        subdomain_count = len(subdomains)
        subdomain_str = " ".join(subdomains).lower()

        contexts = []

        if subdomain_count > 50:
            contexts.append("Large enterprise with complex infrastructure")
        elif subdomain_count > 20:
            contexts.append("Medium-sized organization with multiple services")
        else:
            contexts.append("Small to medium organization")

        if any(word in subdomain_str for word in ["dev", "staging", "test"]):
            contexts.append("Active development environment")

        if any(word in subdomain_str for word in ["api", "service", "microservice"]):
            contexts.append("API-driven architecture")

        return "; ".join(contexts)

    async def _analyze_attack_surface(
        self,
        subdomains: List[str],
        live_hosts: List[Dict] = None
    ) -> AttackSurfaceAnalysis:
        """Analyze attack surface from subdomain patterns"""

        high_value_targets = []
        security_risks = []
        suspicious_patterns = []

        # Analyze subdomain patterns
        for subdomain in subdomains:
            domain_part = subdomain.lower()

            # Check for high-value targets
            for pattern_type, patterns in self.security_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, domain_part):
                        if pattern_type in ["admin_panels", "api_endpoints"]:
                            high_value_targets.append(subdomain)
                        elif pattern_type in ["development", "backup_systems"]:
                            security_risks.append(f"{subdomain} - {pattern_type}")
                        elif pattern_type == "internal_services":
                            suspicious_patterns.append(f"{subdomain} - potential internal service")

        # Analyze live hosts for additional risks
        if live_hosts:
            for host in live_hosts:
                url = host.get("url", "")
                status = host.get("status_code", 0)
                title = host.get("title", "").lower()

                # Check for exposed services
                if status == 200:
                    if any(keyword in title for keyword in ["login", "admin", "dashboard"]):
                        high_value_targets.append(url)
                    elif any(keyword in title for keyword in ["dev", "test", "staging"]):
                        security_risks.append(f"{url} - exposed development environment")

                # Check for redirects that might indicate misconfigurations
                elif status in [301, 302, 303, 307, 308]:
                    security_risks.append(f"{url} - redirect analysis needed")

        return AttackSurfaceAnalysis(
            high_value_targets=list(set(high_value_targets)),
            security_risks=list(set(security_risks)),
            suspicious_patterns=list(set(suspicious_patterns)),
            confidence=0.85
        )

    async def _analyze_technology_stack(
        self,
        technologies: List[str],
        live_hosts: List[Dict] = None
    ) -> TechnologyInsights:
        """Analyze technology stack for vulnerabilities"""

        vulnerabilities = []
        attack_vectors = []
        testing_tools = set()

        # Analyze detected technologies
        for tech in technologies:
            tech_lower = tech.lower()

            for tech_name, tech_data in self.technology_signatures.items():
                if tech_name in tech_lower:
                    vulnerabilities.extend(tech_data["common_vulns"])
                    attack_vectors.extend(tech_data["attack_vectors"])
                    testing_tools.update(tech_data["testing_tools"])

        # Analyze server headers from live hosts
        servers = []
        if live_hosts:
            for host in live_hosts:
                server = host.get("server", "")
                if server:
                    servers.append(server.lower())

        # Create stack summary
        tech_count = len(technologies)
        server_count = len(set(servers))
        stack_summary = f"Detected {tech_count} technologies across {server_count} different server types"

        if not vulnerabilities:
            vulnerabilities = ["No specific vulnerabilities identified in technology stack"]

        if not attack_vectors:
            attack_vectors = ["Standard web application testing approaches"]

        return TechnologyInsights(
            stack_summary=stack_summary,
            vulnerabilities=list(set(vulnerabilities)),
            attack_vectors=list(set(attack_vectors)),
            testing_tools=list(testing_tools) or ["burp", "nmap", "nuclei"]
        )

    async def _analyze_naming_patterns(
        self,
        subdomains: List[str],
        target: str
    ) -> NamingPatternAnalysis:
        """Analyze subdomain naming patterns"""

        conventions = []
        predicted_subdomains = []
        internal_schemes = []
        anomalies = []

        # Extract naming patterns
        patterns = {}
        for subdomain in subdomains:
            # Remove target domain
            sub_part = subdomain.replace(f".{target}", "").replace(target, "")

            # Analyze structure
            if '-' in sub_part:
                patterns['hyphenated'] = patterns.get('hyphenated', 0) + 1
            if any(char.isdigit() for char in sub_part):
                patterns['numbered'] = patterns.get('numbered', 0) + 1
            if len(sub_part.split('.')) > 1:
                patterns['multi_level'] = patterns.get('multi_level', 0) + 1

        # Identify conventions
        total_subs = len(subdomains)
        if total_subs > 0:
            for pattern, count in patterns.items():
                if count / total_subs > 0.3:  # More than 30% follow this pattern
                    conventions.append(f"{pattern.replace('_', ' ').title()} naming (common)")

        # Predict additional subdomains based on patterns
        common_prefixes = ['www', 'api', 'admin', 'dev', 'test', 'mail', 'blog']
        existing_prefixes = set()

        for subdomain in subdomains:
            prefix = subdomain.split('.')[0]
            existing_prefixes.add(prefix)

        for prefix in common_prefixes:
            if prefix not in existing_prefixes:
                predicted_subdomains.append(f"{prefix}.{target}")

        # Identify potential internal schemes
        for subdomain in subdomains:
            if any(pattern in subdomain.lower() for pattern in ['internal', 'corp', 'employee']):
                internal_schemes.append(f"Internal naming detected: {subdomain}")

        # Identify anomalies
        for subdomain in subdomains:
            if len(subdomain.split('.')[0]) > 20:  # Very long subdomain
                anomalies.append(f"Unusually long subdomain: {subdomain}")
            elif any(char in subdomain for char in ['_', '*', '+']):
                anomalies.append(f"Special characters detected: {subdomain}")

        return NamingPatternAnalysis(
            conventions=conventions or ["Standard domain naming conventions"],
            predicted_subdomains=predicted_subdomains[:10],  # Limit predictions
            internal_schemes=internal_schemes,
            anomalies=anomalies[:5]  # Limit anomalies
        )

    def _generate_local_recommendations(
        self,
        attack_surface: AttackSurfaceAnalysis,
        technology_insights: TechnologyInsights,
        naming_patterns: NamingPatternAnalysis
    ) -> List[SecurityRecommendation]:
        """Generate recommendations based on pattern analysis"""

        recommendations = []

        # High-value target recommendations
        if attack_surface.high_value_targets:
            recommendations.append(SecurityRecommendation(
                priority="high",
                target=attack_surface.high_value_targets[0] if attack_surface.high_value_targets else "admin endpoints",
                action="Test admin panels and API endpoints for authentication bypass and privilege escalation",
                tools=["burp", "nuclei", "ffuf"],
                rationale="Admin panels and APIs are high-value targets for privilege escalation",
                estimated_time="2-4 hours"
            ))

        # Development environment recommendations
        dev_risks = [risk for risk in attack_surface.security_risks if 'dev' in risk.lower()]
        if dev_risks:
            recommendations.append(SecurityRecommendation(
                priority="high",
                target="development environments",
                action="Check development environments for exposed functionality and debug information",
                tools=["dirb", "gobuster", "burp"],
                rationale="Development environments often have weaker security controls",
                estimated_time="1-2 hours"
            ))

        # Technology-specific recommendations
        if technology_insights.vulnerabilities and technology_insights.vulnerabilities[0] != "No specific vulnerabilities identified in technology stack":
            recommendations.append(SecurityRecommendation(
                priority="medium",
                target="technology stack",
                action=f"Test for technology-specific vulnerabilities: {', '.join(technology_insights.vulnerabilities[:3])}",
                tools=technology_insights.testing_tools[:3],
                rationale="Detected technologies have known vulnerability patterns",
                estimated_time="3-5 hours"
            ))

        # Predicted subdomain testing
        if naming_patterns.predicted_subdomains:
            recommendations.append(SecurityRecommendation(
                priority="low",
                target="predicted subdomains",
                action=f"Test predicted subdomains: {', '.join(naming_patterns.predicted_subdomains[:5])}",
                tools=["subfinder", "httpx", "nuclei"],
                rationale="Based on naming patterns, these subdomains might exist",
                estimated_time="30 minutes"
            ))

        return recommendations

    def _generate_next_steps(
        self,
        subdomain_count: int,
        live_host_count: int,
        tech_count: int
    ) -> List[str]:
        """Generate next steps based on analysis results"""

        next_steps = []

        if live_host_count > 0:
            next_steps.append(f"Begin testing {live_host_count} live hosts for common vulnerabilities")

        if subdomain_count > live_host_count:
            next_steps.append(f"Investigate {subdomain_count - live_host_count} non-responsive subdomains for subdomain takeover")

        if tech_count > 0:
            next_steps.append(f"Research specific vulnerabilities for {tech_count} detected technologies")

        next_steps.extend([
            "Set up automated monitoring for new subdomains",
            "Document all findings and create testing plan",
            "Prioritize testing based on business impact"
        ])

        return next_steps[:5]  # Limit to 5 next steps

    def format_analysis_report(self, analysis: ComprehensiveAnalysis) -> str:
        """Format analysis results into a readable report"""

        report = f"🎯 **Pattern-Based Reconnaissance Analysis - {analysis.target}**\n"
        report += f"**Generated:** {analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"**Application Type:** {analysis.application_type}\n"
        report += f"**Confidence:** {analysis.overall_confidence:.1%}\n\n"

        # Business Context
        if analysis.business_context and analysis.business_context != "Business context not determined":
            report += f"💼 **Business Context**\n{analysis.business_context}\n\n"

        # Attack Surface
        report += "🎯 **Attack Surface Analysis**\n"
        if analysis.attack_surface.high_value_targets:
            report += f"**High-Value Targets ({len(analysis.attack_surface.high_value_targets)}):**\n"
            for target in analysis.attack_surface.high_value_targets[:5]:
                report += f"• {target}\n"

        if analysis.attack_surface.security_risks:
            report += f"\n**Security Risks ({len(analysis.attack_surface.security_risks)}):**\n"
            for risk in analysis.attack_surface.security_risks[:5]:
                report += f"⚠️ {risk}\n"

        # Priority Targets
        if analysis.target_priorities:
            report += f"\n🚀 **Priority Targets (Top 5)**\n"
            for i, target in enumerate(analysis.target_priorities[:5], 1):
                priority_emoji = "🔥" if target.priority_score >= 9.0 else "⚡" if target.priority_score >= 8.0 else "📍"
                report += f"{priority_emoji} **{i}. {target.subdomain}** (Score: {target.priority_score:.1f})\n"
                report += f"   • **Potential:** {target.vulnerability_potential}\n"
                report += f"   • **Difficulty:** {target.difficulty.title()}\n"
                report += f"   • **Time:** {target.estimated_time}\n"
                report += f"   • **Reasoning:** {target.reasoning}\n\n"

        # Live Host Analysis
        if analysis.live_host_analysis.high_value_targets:
            report += f"🌐 **Live Host Intelligence**\n"
            report += f"**High-Value Live Targets ({len(analysis.live_host_analysis.high_value_targets)}):**\n"
            for target in analysis.live_host_analysis.high_value_targets[:3]:
                report += f"• {target.get('url', 'N/A')} - {target.get('type', 'Unknown')} (Security Score: {target.get('security_score', 0):.1f})\n"

            if analysis.live_host_analysis.security_findings:
                report += f"\n**Security Findings:**\n"
                for finding in analysis.live_host_analysis.security_findings[:3]:
                    report += f"⚠️ {finding}\n"

        # Technology Insights
        report += f"\n🔧 **Technology Analysis**\n"
        report += f"**Stack:** {analysis.technology_insights.stack_summary}\n"

        if analysis.technology_insights.vulnerabilities and analysis.technology_insights.vulnerabilities[0] != "No specific vulnerabilities identified in technology stack":
            report += f"**Key Vulnerabilities:**\n"
            for vuln in analysis.technology_insights.vulnerabilities[:3]:
                report += f"• {vuln}\n"

        # Recommendations
        report += f"\n📋 **Priority Recommendations**\n"
        high_priority = [r for r in analysis.recommendations if r.priority == "high"]
        medium_priority = [r for r in analysis.recommendations if r.priority == "medium"]

        if high_priority:
            report += f"**🔥 High Priority ({len(high_priority)}):**\n"
            for rec in high_priority[:3]:
                report += f"• {rec.action}\n"
                report += f"  Tools: {', '.join(rec.tools[:3])}\n"
                report += f"  Time: {rec.estimated_time}\n\n"

        if medium_priority:
            report += f"**📈 Medium Priority ({len(medium_priority)}):**\n"
            for rec in medium_priority[:2]:
                report += f"• {rec.action}\n"

        # Next Steps
        report += f"\n🚀 **Next Steps:**\n"
        for step in analysis.next_steps:
            report += f"• {step}\n"

        return report


def create_pattern_analyzer() -> PatternAnalyzer:
    """
    Factory function to create pattern analyzer

    Returns:
        Configured PatternAnalyzer instance
    """
    return PatternAnalyzer()
