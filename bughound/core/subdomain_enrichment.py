"""
Subdomain Enrichment System for BugHound

This module provides intelligent analysis and prioritization of discovered subdomains:
- Identifies interesting subdomains (api*, admin*, dev*, staging*)
- Checks for subdomain takeover possibilities
- Groups related subdomains by function and infrastructure
- Assigns priority scores based on security research value
- Detects technology stacks and services

Designed for bug bounty hunters and security researchers.
"""

import asyncio
import logging
import re
import socket
import ssl
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import dns.resolver
import dns.exception

from .subdomain_discovery import SubdomainResult, DiscoveryStatistics

logger = logging.getLogger(__name__)


@dataclass
class EnrichedSubdomain:
    """Enhanced subdomain result with enrichment data"""
    # Base subdomain data
    subdomain: SubdomainResult
    
    # Enrichment data
    priority_score: int = 0
    interest_level: str = "standard"  # critical, high, medium, low, standard
    technology_stack: List[str] = field(default_factory=list)
    service_type: str = "unknown"
    security_notes: List[str] = field(default_factory=list)
    takeover_risk: str = "none"  # high, medium, low, none
    related_subdomains: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    https_available: bool = False
    certificates: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichmentStatistics:
    """Statistics about the enrichment process"""
    total_processed: int = 0
    critical_findings: int = 0
    high_priority: int = 0
    medium_priority: int = 0
    low_priority: int = 0
    takeover_risks: int = 0
    technology_detections: Dict[str, int] = field(default_factory=dict)
    service_types: Dict[str, int] = field(default_factory=dict)


class SubdomainEnrichment:
    """Advanced subdomain analysis and enrichment engine"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        
        # Priority scoring patterns
        self.priority_patterns = {
            "critical": {
                "patterns": [
                    "admin", "administrator", "root", "superuser", "su",
                    "phpmyadmin", "adminer", "cpanel", "plesk", "directadmin",
                    "jenkins", "gitlab-admin", "sonarqube", "nexus-admin",
                    "grafana", "kibana", "elasticsearch-admin", "redis-admin",
                    "database", "db-admin", "mysql-admin", "postgres-admin",
                    "vpn-admin", "firewall-admin", "security-admin"
                ],
                "score": 100
            },
            "high": {
                "patterns": [
                    "api", "rest", "graphql", "webhook", "service", "microservice",
                    "auth", "authentication", "oauth", "sso", "login", "signin",
                    "payment", "pay", "billing", "finance", "wallet",
                    "internal", "private", "intranet", "corp", "corporate",
                    "dev", "development", "staging", "stage", "test", "testing",
                    "backup", "backups", "archive", "dump", "export",
                    "ftp", "sftp", "ssh", "vpn", "remote", "rdp"
                ],
                "score": 75
            },
            "medium": {
                "patterns": [
                    "qa", "quality", "uat", "acceptance", "beta", "alpha",
                    "demo", "sandbox", "lab", "labs", "experimental",
                    "support", "help", "helpdesk", "ticket", "tickets",
                    "docs", "documentation", "wiki", "kb", "knowledge",
                    "blog", "news", "forum", "community", "social",
                    "mail", "email", "smtp", "imap", "webmail", "exchange",
                    "monitor", "monitoring", "status", "health", "metrics"
                ],
                "score": 50
            },
            "low": {
                "patterns": [
                    "www", "web", "website", "site", "homepage", "home",
                    "cdn", "static", "assets", "images", "img", "media",
                    "css", "js", "javascript", "fonts", "files",
                    "cache", "proxy", "lb", "loadbalancer", "nginx",
                    "blog-old", "old", "legacy", "deprecated", "unused"
                ],
                "score": 25
            }
        }
        
        # Technology detection patterns
        self.technology_patterns = {
            "jenkins": ["jenkins", "ci", "build", "deploy"],
            "gitlab": ["gitlab", "git", "repo", "repository"],
            "docker": ["docker", "container", "registry", "harbor"],
            "kubernetes": ["k8s", "kubernetes", "kube", "cluster"],
            "elasticsearch": ["elastic", "es", "kibana", "logstash"],
            "grafana": ["grafana", "prometheus", "metrics", "dashboard"],
            "wordpress": ["wp", "wordpress", "blog", "cms"],
            "jira": ["jira", "atlassian", "issue", "ticket"],
            "confluence": ["confluence", "wiki", "docs", "documentation"],
            "sonarqube": ["sonar", "sonarqube", "quality", "code-analysis"],
            "nexus": ["nexus", "repository", "artifact", "maven"],
            "database": ["db", "database", "mysql", "postgres", "mongo", "redis"],
            "mail": ["mail", "smtp", "imap", "exchange", "postfix"],
            "proxy": ["proxy", "nginx", "apache", "haproxy", "traefik"],
            "monitoring": ["monitor", "nagios", "zabbix", "icinga", "sensu"]
        }
        
        # Service type classification
        self.service_types = {
            "administration": ["admin", "administrator", "panel", "console", "control"],
            "api": ["api", "rest", "graphql", "service", "microservice", "webhook"],
            "authentication": ["auth", "sso", "oauth", "login", "signin", "ldap"],
            "development": ["dev", "development", "staging", "test", "qa", "beta"],
            "infrastructure": ["dns", "ns", "mx", "smtp", "ftp", "vpn", "proxy"],
            "monitoring": ["monitor", "status", "health", "metrics", "logs", "alerts"],
            "content": ["www", "web", "blog", "cms", "wiki", "docs", "static"],
            "communication": ["mail", "email", "chat", "forum", "support", "help"],
            "security": ["firewall", "ids", "ips", "security", "vault", "secrets"],
            "database": ["db", "database", "mysql", "postgres", "mongo", "redis", "elastic"]
        }
        
        # Subdomain takeover signatures
        self.takeover_signatures = {
            "high_risk": [
                "github.io", "herokuapp.com", "s3.amazonaws.com", "s3-website",
                "cloudfront.net", "azurewebsites.net", "appspot.com"
            ],
            "medium_risk": [
                "netlify.com", "vercel.app", "surge.sh", "firebase.com",
                "bitbucket.io", "gitlab.io", "ghost.io"
            ],
            "low_risk": [
                "wordpress.com", "blogspot.com", "tumblr.com", "shopify.com"
            ]
        }
        
        # Security-relevant patterns
        self.security_patterns = {
            "exposed_services": [
                "phpmyadmin", "adminer", "mysql", "postgres", "redis", "mongodb",
                "elasticsearch", "kibana", "grafana", "jenkins", "sonarqube"
            ],
            "development_exposure": [
                "dev", "development", "staging", "test", "qa", "beta", "alpha",
                "sandbox", "demo", "lab", "experimental"
            ],
            "backup_exposure": [
                "backup", "backups", "archive", "dump", "export", "snapshot"
            ],
            "internal_exposure": [
                "internal", "private", "intranet", "corp", "corporate", "office"
            ]
        }
    
    async def enrich_subdomains(
        self, 
        subdomains: List[SubdomainResult],
        options: Dict[str, Any] = None
    ) -> Tuple[List[EnrichedSubdomain], EnrichmentStatistics]:
        """
        Enrich subdomain results with intelligence and prioritization
        
        Args:
            subdomains: List of discovered subdomains
            options: Enrichment options
            
        Returns:
            Tuple of (enriched_subdomains, statistics)
        """
        if not options:
            options = {}
        
        logger.info(f"Starting enrichment for {len(subdomains)} subdomains")
        
        enriched_results = []
        stats = EnrichmentStatistics()
        stats.total_processed = len(subdomains)
        
        # Process subdomains in batches
        batch_size = options.get("batch_size", 20)
        
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            
            # Process batch concurrently
            tasks = [self._enrich_single_subdomain(subdomain, options) for subdomain in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, EnrichedSubdomain):
                    enriched_results.append(result)
                    self._update_statistics(result, stats)
                elif isinstance(result, Exception):
                    logger.debug(f"Enrichment error: {result}")
        
        # Group related subdomains
        self._group_related_subdomains(enriched_results)
        
        # Sort by priority score
        enriched_results.sort(key=lambda x: x.priority_score, reverse=True)
        
        logger.info(f"Enrichment complete: {len(enriched_results)} subdomains processed")
        
        return enriched_results, stats
    
    async def _enrich_single_subdomain(
        self, 
        subdomain: SubdomainResult,
        options: Dict[str, Any]
    ) -> EnrichedSubdomain:
        """Enrich a single subdomain with intelligence"""
        
        enriched = EnrichedSubdomain(subdomain=subdomain)
        
        # Basic analysis
        domain_name = subdomain.domain.lower()
        
        # Priority scoring
        enriched.priority_score = self._calculate_priority_score(domain_name)
        enriched.interest_level = self._determine_interest_level(enriched.priority_score)
        
        # Technology detection
        enriched.technology_stack = self._detect_technologies(domain_name)
        
        # Service type classification
        enriched.service_type = self._classify_service_type(domain_name)
        
        # Security analysis
        enriched.security_notes = self._analyze_security_implications(domain_name)
        
        # Takeover risk assessment
        enriched.takeover_risk = self._assess_takeover_risk(subdomain)
        
        # HTTP/HTTPS probing (if enabled)
        if options.get("http_probing", False):
            await self._probe_http_services(enriched)
        
        # Certificate analysis (if enabled)
        if options.get("certificate_analysis", False):
            await self._analyze_certificates(enriched)
        
        return enriched
    
    def _calculate_priority_score(self, domain_name: str) -> int:
        """Calculate priority score based on subdomain name"""
        
        base_score = 0
        
        for priority_level, config in self.priority_patterns.items():
            for pattern in config["patterns"]:
                if pattern in domain_name:
                    base_score = max(base_score, config["score"])
        
        # Bonus for multiple matches
        total_matches = 0
        for priority_level, config in self.priority_patterns.items():
            for pattern in config["patterns"]:
                if pattern in domain_name:
                    total_matches += 1
        
        if total_matches > 1:
            base_score += min(total_matches * 5, 25)  # Max 25 bonus points
        
        # Penalty for very long or complex names (often automated/less interesting)
        if len(domain_name) > 20:
            base_score -= 10
        
        return max(0, base_score)
    
    def _determine_interest_level(self, priority_score: int) -> str:
        """Determine interest level based on priority score"""
        
        if priority_score >= 90:
            return "critical"
        elif priority_score >= 70:
            return "high"
        elif priority_score >= 45:
            return "medium"
        elif priority_score >= 20:
            return "low"
        else:
            return "standard"
    
    def _detect_technologies(self, domain_name: str) -> List[str]:
        """Detect technologies based on subdomain name"""
        
        detected = []
        
        for technology, patterns in self.technology_patterns.items():
            for pattern in patterns:
                if pattern in domain_name:
                    detected.append(technology)
                    break  # Only add each technology once
        
        return detected
    
    def _classify_service_type(self, domain_name: str) -> str:
        """Classify the type of service based on subdomain name"""
        
        for service_type, patterns in self.service_types.items():
            for pattern in patterns:
                if pattern in domain_name:
                    return service_type
        
        return "unknown"
    
    def _analyze_security_implications(self, domain_name: str) -> List[str]:
        """Analyze potential security implications"""
        
        security_notes = []
        
        for category, patterns in self.security_patterns.items():
            for pattern in patterns:
                if pattern in domain_name:
                    if category == "exposed_services":
                        security_notes.append(f"Potentially exposed {pattern} service")
                    elif category == "development_exposure":
                        security_notes.append("Development/testing environment exposed")
                    elif category == "backup_exposure":
                        security_notes.append("Backup/archive system potentially exposed")
                    elif category == "internal_exposure":
                        security_notes.append("Internal system potentially exposed")
                    break
        
        return security_notes
    
    def _assess_takeover_risk(self, subdomain: SubdomainResult) -> str:
        """Assess subdomain takeover risk"""
        
        if not subdomain.cname:
            return "none"
        
        cname_lower = subdomain.cname.lower()
        
        # Check for high-risk signatures
        for signature in self.takeover_signatures["high_risk"]:
            if signature in cname_lower:
                return "high"
        
        # Check for medium-risk signatures
        for signature in self.takeover_signatures["medium_risk"]:
            if signature in cname_lower:
                return "medium"
        
        # Check for low-risk signatures
        for signature in self.takeover_signatures["low_risk"]:
            if signature in cname_lower:
                return "low"
        
        # Check if CNAME points to non-resolving domain
        if subdomain.status == "non-resolving" and subdomain.cname:
            return "medium"  # Potential dangling CNAME
        
        return "none"
    
    async def _probe_http_services(self, enriched: EnrichedSubdomain):
        """Probe HTTP/HTTPS services"""
        
        domain = enriched.subdomain.domain
        
        try:
            # Quick HTTP/HTTPS check using socket
            for port, protocol in [(80, "http"), (443, "https")]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    
                    if result == 0:  # Connection successful
                        if protocol == "https":
                            enriched.https_available = True
                        
                        # Could add HTTP status code checking here
                        enriched.http_status = 200  # Placeholder
                        
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"HTTP probing failed for {domain}: {e}")
    
    async def _analyze_certificates(self, enriched: EnrichedSubdomain):
        """Analyze SSL certificates"""
        
        if not enriched.https_available:
            return
        
        domain = enriched.subdomain.domain
        
        try:
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    enriched.certificates = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": cert.get("version"),
                        "not_after": cert.get("notAfter"),
                        "not_before": cert.get("notBefore")
                    }
                    
        except Exception as e:
            logger.debug(f"Certificate analysis failed for {domain}: {e}")
    
    def _group_related_subdomains(self, enriched_subdomains: List[EnrichedSubdomain]):
        """Group related subdomains based on patterns and IPs"""
        
        # Group by IP address
        ip_groups = {}
        for enriched in enriched_subdomains:
            for ip in enriched.subdomain.ip_addresses:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(enriched.subdomain.domain)
        
        # Update related subdomains
        for enriched in enriched_subdomains:
            related = set()
            
            # Add subdomains sharing IPs
            for ip in enriched.subdomain.ip_addresses:
                if ip in ip_groups:
                    related.update(ip_groups[ip])
            
            # Remove self
            related.discard(enriched.subdomain.domain)
            
            enriched.related_subdomains = list(related)
    
    def _update_statistics(self, enriched: EnrichedSubdomain, stats: EnrichmentStatistics):
        """Update enrichment statistics"""
        
        # Interest level counts
        if enriched.interest_level == "critical":
            stats.critical_findings += 1
        elif enriched.interest_level == "high":
            stats.high_priority += 1
        elif enriched.interest_level == "medium":
            stats.medium_priority += 1
        elif enriched.interest_level == "low":
            stats.low_priority += 1
        
        # Takeover risk counts
        if enriched.takeover_risk in ["high", "medium"]:
            stats.takeover_risks += 1
        
        # Technology detection counts
        for tech in enriched.technology_stack:
            stats.technology_detections[tech] = stats.technology_detections.get(tech, 0) + 1
        
        # Service type counts
        if enriched.service_type != "unknown":
            stats.service_types[enriched.service_type] = stats.service_types.get(enriched.service_type, 0) + 1
    
    def format_enriched_results(
        self, 
        enriched_subdomains: List[EnrichedSubdomain],
        stats: EnrichmentStatistics
    ) -> Dict[str, Any]:
        """Format enriched results for output"""
        
        # Group by interest level
        grouped_results = {
            "critical": [],
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "standard": []
        }
        
        for enriched in enriched_subdomains:
            level = enriched.interest_level
            if level == "critical":
                key = "critical"
            elif level == "high":
                key = "high_priority"
            elif level == "medium":
                key = "medium_priority"
            elif level == "low":
                key = "low_priority"
            else:
                key = "standard"
            
            # Format subdomain info
            subdomain_info = {
                "domain": enriched.subdomain.domain,
                "ip_addresses": enriched.subdomain.ip_addresses,
                "priority_score": enriched.priority_score,
                "service_type": enriched.service_type,
                "technology_stack": enriched.technology_stack,
                "security_notes": enriched.security_notes,
                "takeover_risk": enriched.takeover_risk
            }
            
            grouped_results[key].append(subdomain_info)
        
        # Compile statistics
        formatted_stats = {
            "total_processed": stats.total_processed,
            "critical_findings": stats.critical_findings,
            "high_priority": stats.high_priority,
            "medium_priority": stats.medium_priority,
            "low_priority": stats.low_priority,
            "takeover_risks": stats.takeover_risks,
            "technology_detections": dict(stats.technology_detections),
            "service_types": dict(stats.service_types)
        }
        
        return {
            "subdomains": grouped_results,
            "statistics": formatted_stats
        }