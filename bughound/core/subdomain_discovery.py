"""
Comprehensive Subdomain Discovery System for BugHound

This module provides a complete subdomain enumeration workflow:
1. Passive Collection (subfinder, crt.sh, assetfinder)
2. Permutation Generation (altdns patterns)
3. DNS Validation & IP Grouping
4. Intelligent Prioritization

Inspired by Sn1per and other proven reconnaissance tools.
"""

import asyncio
import logging
import json
import ssl
import socket
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import dns.resolver
import dns.exception

from ..tools.recon.subfinder import SubfinderTool

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Represents a discovered subdomain with metadata"""
    domain: str
    source: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    status: str = "unknown"  # resolving, non-resolving, timeout
    priority: str = "standard"  # high, medium, low, standard
    category: str = "standard"  # development, api, admin, infrastructure, standard
    takeover_possible: bool = False
    ports_open: List[int] = field(default_factory=list)
    discovered_at: Optional[str] = None


@dataclass
class DiscoveryStatistics:
    """Statistics about the discovery process"""
    total_found: int = 0
    resolving: int = 0
    non_resolving: int = 0
    sources: Dict[str, int] = field(default_factory=dict)
    categories: Dict[str, int] = field(default_factory=dict)
    priorities: Dict[str, int] = field(default_factory=dict)
    duration: float = 0.0


class SubdomainDiscovery:
    """Comprehensive subdomain discovery engine"""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.subfinder = SubfinderTool(timeout=timeout)
        
        # Resolver configuration
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        
        # Pattern definitions for categorization
        self.priority_patterns = {
            "high": [
                "admin", "administrator", "api", "auth", "authentication",
                "backend", "dashboard", "internal", "private", "vpn",
                "ftp", "ssh", "database", "db", "mysql", "postgres",
                "jenkins", "gitlab", "sonar", "nexus", "artifactory"
            ],
            "medium": [
                "dev", "development", "staging", "test", "testing",
                "qa", "quality", "beta", "alpha", "pre", "preprod",
                "uat", "acceptance", "demo", "sandbox"
            ],
            "low": [
                "cdn", "static", "assets", "images", "img", "css", "js",
                "media", "files", "download", "uploads", "backup"
            ]
        }
        
        self.category_patterns = {
            "api": ["api", "rest", "graphql", "webhook", "service"],
            "admin": ["admin", "administrator", "panel", "console", "control"],
            "development": ["dev", "development", "staging", "test", "qa", "beta"],
            "infrastructure": ["mail", "smtp", "imap", "pop", "dns", "ns", "mx"],
            "security": ["auth", "sso", "oauth", "vpn", "firewall", "ids"],
            "monitoring": ["monitor", "metrics", "logs", "grafana", "kibana", "elastic"]
        }
        
        # Known takeover signatures
        self.takeover_signatures = [
            "github.io", "herokuapp.com", "amazonaws.com", "azurewebsites.net",
            "cloudfront.net", "s3.amazonaws.com", "s3-website"
        ]
    
    async def discover_comprehensive(
        self, 
        target: str, 
        options: Dict[str, Any] = None
    ) -> Tuple[List[SubdomainResult], DiscoveryStatistics]:
        """
        Complete subdomain discovery workflow
        
        Args:
            target: Target domain
            options: Discovery options
            
        Returns:
            Tuple of (subdomains, statistics)
        """
        if not options:
            options = {}
        
        start_time = asyncio.get_event_loop().time()
        
        logger.info(f"Starting comprehensive subdomain discovery for {target}")
        
        # Phase 1: Passive Collection
        logger.info("Phase 1: Passive collection")
        passive_results = await self._passive_collection(target, options)
        
        # Phase 2: Generate Permutations (if enabled)
        if options.get("enable_permutations", True):
            logger.info("Phase 2: Generating permutations")
            permutation_results = await self._generate_permutations(target, passive_results, options)
        else:
            permutation_results = []
        
        # Combine all results
        all_domains = set()
        source_mapping = {}
        
        # Add passive results
        for result in passive_results:
            all_domains.add(result.domain)
            source_mapping[result.domain] = result.source
        
        # Add permutation results
        for domain in permutation_results:
            all_domains.add(domain)
            if domain not in source_mapping:
                source_mapping[domain] = "permutation"
        
        # Phase 3: DNS Validation & Enrichment
        logger.info("Phase 3: DNS validation and enrichment")
        validated_results = await self._validate_and_enrich(all_domains, source_mapping, target)
        
        # Calculate statistics
        end_time = asyncio.get_event_loop().time()
        stats = self._calculate_statistics(validated_results, end_time - start_time)
        
        logger.info(f"Discovery complete: {stats.total_found} subdomains found, {stats.resolving} resolving")
        
        return validated_results, stats
    
    async def _passive_collection(
        self, 
        target: str, 
        options: Dict[str, Any]
    ) -> List[SubdomainResult]:
        """Phase 1: Passive subdomain collection"""
        results = []
        
        # Subfinder collection
        try:
            subfinder_options = {
                "threads": options.get("threads", 20),
                "timeout": options.get("subfinder_timeout", 180),
                "verbose": options.get("verbose", False),
                "sources": options.get("subfinder_sources", "")
            }
            
            subfinder_result = await self.subfinder.execute(target, subfinder_options)
            
            if subfinder_result.success:
                data = subfinder_result.data
                for subdomain_info in data.get("subdomains", []):
                    result = SubdomainResult(
                        domain=subdomain_info["domain"],
                        source=f"subfinder-{subdomain_info['source']}"
                    )
                    results.append(result)
                    
                logger.info(f"Subfinder found {len(results)} subdomains")
            else:
                logger.warning(f"Subfinder failed: {subfinder_result.error}")
                
        except Exception as e:
            logger.error(f"Subfinder collection failed: {e}")
        
        # Certificate Transparency (crt.sh) - simplified implementation
        try:
            crt_results = await self._query_certificate_transparency(target)
            for domain in crt_results:
                result = SubdomainResult(domain=domain, source="crt.sh")
                results.append(result)
            
            logger.info(f"Certificate transparency found {len(crt_results)} additional subdomains")
            
        except Exception as e:
            logger.error(f"Certificate transparency collection failed: {e}")
        
        return results
    
    async def _query_certificate_transparency(self, target: str) -> List[str]:
        """Query certificate transparency logs (simplified implementation)"""
        import aiohttp
        
        domains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            
                            # Parse certificate names
                            for name in name_value.split("\n"):
                                name = name.strip()
                                if name and target in name:
                                    # Remove wildcards
                                    if name.startswith("*."):
                                        name = name[2:]
                                    
                                    # Validate domain format
                                    if self._is_valid_domain(name):
                                        domains.add(name)
                        
        except Exception as e:
            logger.error(f"crt.sh query failed: {e}")
        
        return list(domains)
    
    async def _generate_permutations(
        self, 
        target: str, 
        existing_results: List[SubdomainResult],
        options: Dict[str, Any]
    ) -> List[str]:
        """Phase 2: Generate subdomain permutations"""
        
        # Extract existing subdomains for pattern analysis
        existing_domains = {result.domain for result in existing_results}
        
        permutations = set()
        
        # Common prefixes and suffixes
        prefixes = [
            "api", "app", "web", "www", "dev", "staging", "test", "qa",
            "prod", "production", "admin", "administrator", "panel",
            "blog", "shop", "store", "mail", "email", "smtp", "imap",
            "ftp", "vpn", "cdn", "static", "media", "images", "assets",
            "auth", "sso", "oauth", "login", "portal", "dashboard",
            "monitor", "status", "health", "metrics", "logs"
        ]
        
        suffixes = [
            "api", "app", "web", "dev", "staging", "test", "qa",
            "prod", "production", "admin", "panel", "new", "old",
            "v1", "v2", "v3", "backup", "temp", "tmp"
        ]
        
        # Number patterns
        numbers = ["01", "02", "03", "1", "2", "3", "10", "100"]
        
        # Generate permutations
        base_domain = target
        
        # Prefix patterns
        for prefix in prefixes:
            permutations.add(f"{prefix}.{base_domain}")
            
            # With numbers
            for num in numbers:
                permutations.add(f"{prefix}{num}.{base_domain}")
                permutations.add(f"{prefix}-{num}.{base_domain}")
        
        # Suffix patterns (less common but still useful)
        for suffix in suffixes:
            # Extract subdomain from target if exists
            if "." in target:
                parts = target.split(".")
                if len(parts) >= 2:
                    root = ".".join(parts[-2:])  # Get root domain
                    permutations.add(f"{suffix}.{root}")
        
        # Environment-based patterns
        environments = ["dev", "staging", "test", "qa", "prod", "production"]
        services = ["api", "app", "web", "admin", "portal"]
        
        for env in environments:
            for service in services:
                permutations.add(f"{env}-{service}.{base_domain}")
                permutations.add(f"{service}-{env}.{base_domain}")
        
        # Remove already discovered domains
        new_permutations = permutations - existing_domains
        
        # Limit permutations to avoid excessive DNS queries
        max_permutations = options.get("max_permutations", 1000)
        if len(new_permutations) > max_permutations:
            new_permutations = set(list(new_permutations)[:max_permutations])
        
        logger.info(f"Generated {len(new_permutations)} permutations for testing")
        
        return list(new_permutations)
    
    async def _validate_and_enrich(
        self, 
        domains: Set[str], 
        source_mapping: Dict[str, str],
        target: str
    ) -> List[SubdomainResult]:
        """Phase 3: DNS validation and enrichment"""
        
        results = []
        
        # Process domains in batches to avoid overwhelming DNS
        batch_size = 50
        domain_list = list(domains)
        
        for i in range(0, len(domain_list), batch_size):
            batch = domain_list[i:i + batch_size]
            
            # Process batch concurrently
            tasks = [self._validate_domain(domain, source_mapping.get(domain, "unknown"), target) 
                    for domain in batch]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, SubdomainResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.debug(f"Domain validation error: {result}")
        
        return results
    
    async def _validate_domain(
        self, 
        domain: str, 
        source: str,
        target: str
    ) -> Optional[SubdomainResult]:
        """Validate a single domain and enrich with metadata"""
        
        result = SubdomainResult(domain=domain, source=source)
        
        try:
            # DNS resolution
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(None, self.resolver.resolve, domain, 'A')
            result.ip_addresses = [str(answer) for answer in answers]
            result.status = "resolving"
            
            # Try to get CNAME
            try:
                cname_answers = await loop.run_in_executor(None, self.resolver.resolve, domain, 'CNAME')
                if cname_answers:
                    result.cname = str(cname_answers[0])
                    
                    # Check for potential takeover
                    for signature in self.takeover_signatures:
                        if signature in result.cname:
                            result.takeover_possible = True
                            break
                            
            except (dns.exception.DNSException, Exception) as e:
                pass  # No CNAME record OR resolving failed
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result.status = "non-resolving"
        except dns.resolver.Timeout:
            result.status = "timeout"
        except Exception as e:
            logger.debug(f"DNS resolution failed for {domain}: {e}")
            result.status = "error"
        
        # Categorize and prioritize
        result.category = self._categorize_domain(domain)
        result.priority = self._prioritize_domain(domain)
        
        return result
    
    def _categorize_domain(self, domain: str) -> str:
        """Categorize subdomain based on name patterns"""
        domain_lower = domain.lower()
        
        for category, patterns in self.category_patterns.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return category
        
        return "standard"
    
    def _prioritize_domain(self, domain: str) -> str:
        """Assign priority based on subdomain name"""
        domain_lower = domain.lower()
        
        for priority, patterns in self.priority_patterns.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    return priority
        
        return "standard"
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if not domain or len(domain) > 253:
            return False
        
        # Basic format check
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    def _calculate_statistics(
        self, 
        results: List[SubdomainResult], 
        duration: float
    ) -> DiscoveryStatistics:
        """Calculate discovery statistics"""
        
        stats = DiscoveryStatistics()
        stats.total_found = len(results)
        stats.duration = duration
        
        for result in results:
            # Status counts
            if result.status == "resolving":
                stats.resolving += 1
            elif result.status == "non-resolving":
                stats.non_resolving += 1
            
            # Source counts
            source = result.source.split('-')[0]  # Remove subfinder source suffix
            stats.sources[source] = stats.sources.get(source, 0) + 1
            
            # Category counts
            stats.categories[result.category] = stats.categories.get(result.category, 0) + 1
            
            # Priority counts
            stats.priorities[result.priority] = stats.priorities.get(result.priority, 0) + 1
        
        return stats