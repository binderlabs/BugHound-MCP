"""
AltDNS-style Permutation Tool for BugHound

Generates intelligent subdomain permutations based on:
- Common patterns (dev-, staging-, api-, -dev, -staging)
- Number patterns (api1, api2, web01, web02)
- Environment combinations (dev-api, staging-web)
- Wordlist-based mutations
- Custom pattern analysis

Inspired by altdns and other subdomain brute-forcing tools.
"""

import asyncio
import logging
import itertools
from typing import Dict, Any, List, Set, Optional, Tuple
from pathlib import Path
import random

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class AltDNSTool(BaseTool):
    """Advanced subdomain permutation generator"""
    
    def __init__(self, timeout: int = 120):
        super().__init__("altdns", timeout)
        
        # Common subdomain prefixes
        self.prefixes = [
            # Development & Testing
            "dev", "development", "staging", "stage", "test", "testing", 
            "qa", "quality", "uat", "acceptance", "beta", "alpha", "demo",
            "sandbox", "lab", "labs", "experimental", "canary",
            
            # Infrastructure
            "api", "app", "web", "www", "www2", "www3", "portal", "gateway",
            "service", "services", "micro", "backend", "frontend",
            
            # Administration
            "admin", "administrator", "panel", "control", "console", "manage",
            "dashboard", "cpanel", "wp-admin", "phpmyadmin",
            
            # Communication
            "mail", "email", "smtp", "imap", "pop", "pop3", "webmail",
            "mx", "mx1", "mx2", "exchange", "outlook",
            
            # Security & Authentication
            "auth", "authentication", "sso", "oauth", "login", "signin",
            "vpn", "ssl", "secure", "security", "ids", "firewall",
            
            # Content & Media
            "blog", "news", "media", "images", "img", "static", "assets",
            "cdn", "content", "files", "download", "upload", "uploads",
            
            # Monitoring & Operations
            "monitor", "monitoring", "status", "health", "metrics", "stats",
            "logs", "logging", "alerts", "grafana", "kibana", "elastic",
            
            # Business Functions
            "shop", "store", "ecommerce", "payment", "pay", "billing",
            "support", "help", "docs", "documentation", "wiki", "kb",
            
            # Network & DNS
            "ns", "ns1", "ns2", "dns", "resolver", "proxy", "cache",
            "lb", "loadbalancer", "cluster", "node", "worker",
            
            # Databases
            "db", "database", "mysql", "postgres", "mongo", "redis",
            "elastic", "solr", "search", "index"
        ]
        
        # Common suffixes
        self.suffixes = [
            # Environment indicators
            "dev", "development", "staging", "stage", "test", "testing",
            "qa", "prod", "production", "live",
            
            # Version indicators
            "v1", "v2", "v3", "api", "new", "old", "legacy", "next",
            
            # Instance indicators
            "1", "2", "3", "01", "02", "03", "backup", "bak", "temp", "tmp"
        ]
        
        # Number patterns
        self.numbers = [
            "1", "2", "3", "4", "5", "10", "20", "100",
            "01", "02", "03", "04", "05", "001", "002", "003"
        ]
        
        # Environment combinations
        self.environments = ["dev", "staging", "test", "qa", "prod", "production"]
        self.services = ["api", "app", "web", "admin", "portal", "service"]
        
        # Common separators
        self.separators = ["-", "_", ""]
        
        # Advanced patterns
        self.advanced_patterns = [
            # Regional patterns
            "us", "eu", "asia", "east", "west", "north", "south",
            "us-east", "us-west", "eu-west", "ap-south",
            
            # Cloud patterns
            "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
            
            # Mobile patterns
            "mobile", "m", "app", "ios", "android",
            
            # Internal patterns
            "internal", "int", "intranet", "corp", "corporate", "office"
        ]
        
        # Mutation strategies
        self.mutation_strategies = [
            "prefix_addition", "suffix_addition", "number_insertion",
            "separator_variation", "environment_combination", "advanced_patterns"
        ]
    
    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        """
        Generate subdomain permutations for a target domain
        
        Args:
            target: Target domain
            options: Generation options
            
        Returns:
            ToolResult with generated permutations
        """
        try:
            logger.info(f"Generating permutations for {target}")
            
            # Extract options
            max_permutations = options.get("max_permutations", 2000)
            strategies = options.get("strategies", self.mutation_strategies)
            custom_wordlist = options.get("custom_wordlist", [])
            existing_subdomains = set(options.get("existing_subdomains", []))
            
            # Generate permutations using multiple strategies
            all_permutations = set()
            
            for strategy in strategies:
                strategy_perms = await self._generate_by_strategy(
                    target, strategy, custom_wordlist
                )
                all_permutations.update(strategy_perms)
                
                logger.debug(f"Strategy {strategy}: generated {len(strategy_perms)} permutations")
            
            # Remove existing subdomains
            new_permutations = all_permutations - existing_subdomains
            
            # Limit results
            if len(new_permutations) > max_permutations:
                # Prioritize permutations by strategy importance
                prioritized_perms = self._prioritize_permutations(
                    list(new_permutations), max_permutations
                )
                new_permutations = set(prioritized_perms)
            
            # Prepare result data
            result_data = {
                "permutations": sorted(list(new_permutations)),
                "total_generated": len(all_permutations),
                "new_permutations": len(new_permutations),
                "strategies_used": strategies,
                "target": target,
                "statistics": self._calculate_strategy_stats(all_permutations, target)
            }
            
            logger.info(f"Generated {len(new_permutations)} new permutations for {target}")
            
            return ToolResult(
                success=True,
                data=result_data
            )
            
        except Exception as e:
            logger.error(f"Permutation generation failed: {e}")
            return ToolResult(
                success=False,
                error=str(e)
            )
    
    async def _generate_by_strategy(
        self, 
        target: str, 
        strategy: str, 
        custom_wordlist: List[str]
    ) -> Set[str]:
        """Generate permutations using a specific strategy"""
        
        permutations = set()
        base_domain = target
        
        # Extract root domain if target has subdomain
        if target.count('.') > 1:
            parts = target.split('.')
            base_domain = '.'.join(parts[-2:])
        
        if strategy == "prefix_addition":
            permutations.update(self._generate_prefix_permutations(base_domain, custom_wordlist))
            
        elif strategy == "suffix_addition":
            permutations.update(self._generate_suffix_permutations(base_domain, custom_wordlist))
            
        elif strategy == "number_insertion":
            permutations.update(self._generate_number_permutations(base_domain))
            
        elif strategy == "separator_variation":
            permutations.update(self._generate_separator_permutations(base_domain))
            
        elif strategy == "environment_combination":
            permutations.update(self._generate_environment_permutations(base_domain))
            
        elif strategy == "advanced_patterns":
            permutations.update(self._generate_advanced_permutations(base_domain))
        
        return permutations
    
    def _generate_prefix_permutations(self, domain: str, custom_wordlist: List[str]) -> Set[str]:
        """Generate permutations with prefixes"""
        permutations = set()
        
        # Use standard prefixes
        wordlist = self.prefixes + custom_wordlist
        
        for word in wordlist:
            # Simple prefix
            permutations.add(f"{word}.{domain}")
            
            # With numbers
            for num in self.numbers[:5]:  # Limit numbers for prefixes
                permutations.add(f"{word}{num}.{domain}")
                
            # With separators
            for sep in ["-", "_"]:
                permutations.add(f"{word}{sep}1.{domain}")
                permutations.add(f"{word}{sep}2.{domain}")
        
        return permutations
    
    def _generate_suffix_permutations(self, domain: str, custom_wordlist: List[str]) -> Set[str]:
        """Generate permutations with suffixes"""
        permutations = set()
        
        # Extract base for suffix application
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) >= 2:
                base = parts[0]
                rest = '.'.join(parts[1:])
                
                wordlist = self.suffixes + custom_wordlist
                
                for word in wordlist:
                    # Simple suffix
                    permutations.add(f"{base}{word}.{rest}")
                    
                    # With separators
                    for sep in ["-", "_"]:
                        permutations.add(f"{base}{sep}{word}.{rest}")
        
        return permutations
    
    def _generate_number_permutations(self, domain: str) -> Set[str]:
        """Generate permutations with number patterns"""
        permutations = set()
        
        # Common prefixes with numbers
        base_words = ["api", "web", "app", "server", "host", "node", "worker"]
        
        for word in base_words:
            for num in self.numbers:
                permutations.add(f"{word}{num}.{domain}")
                
                # With separators
                for sep in ["-", "_"]:
                    permutations.add(f"{word}{sep}{num}.{domain}")
        
        return permutations
    
    def _generate_separator_permutations(self, domain: str) -> Set[str]:
        """Generate permutations with different separators"""
        permutations = set()
        
        # Common two-word combinations
        combinations = [
            ("api", "v1"), ("api", "v2"), ("web", "app"), ("admin", "panel"),
            ("user", "portal"), ("dev", "api"), ("staging", "web"), ("test", "app")
        ]
        
        for word1, word2 in combinations:
            for sep in self.separators:
                if sep:  # Non-empty separator
                    permutations.add(f"{word1}{sep}{word2}.{domain}")
                else:  # No separator
                    permutations.add(f"{word1}{word2}.{domain}")
        
        return permutations
    
    def _generate_environment_permutations(self, domain: str) -> Set[str]:
        """Generate environment-based permutations"""
        permutations = set()
        
        for env in self.environments:
            for service in self.services:
                for sep in ["-", "_", ""]:
                    # env-service pattern
                    permutations.add(f"{env}{sep}{service}.{domain}")
                    # service-env pattern
                    permutations.add(f"{service}{sep}{env}.{domain}")
        
        return permutations
    
    def _generate_advanced_permutations(self, domain: str) -> Set[str]:
        """Generate advanced pattern permutations"""
        permutations = set()
        
        for pattern in self.advanced_patterns:
            # Simple pattern
            permutations.add(f"{pattern}.{domain}")
            
            # Pattern with common services
            for service in ["api", "web", "app"][:3]:  # Limit to avoid explosion
                for sep in ["-", ""]:
                    permutations.add(f"{pattern}{sep}{service}.{domain}")
                    permutations.add(f"{service}{sep}{pattern}.{domain}")
        
        return permutations
    
    def _prioritize_permutations(self, permutations: List[str], max_count: int) -> List[str]:
        """Prioritize permutations based on likelihood"""
        
        # Priority scoring
        scored_perms = []
        
        for perm in permutations:
            subdomain = perm.split('.')[0]
            score = 0
            
            # High priority patterns
            high_priority = ["api", "admin", "dev", "staging", "test"]
            for pattern in high_priority:
                if pattern in subdomain.lower():
                    score += 10
            
            # Medium priority patterns
            medium_priority = ["app", "web", "portal", "service"]
            for pattern in medium_priority:
                if pattern in subdomain.lower():
                    score += 5
            
            # Number bonus (numbered services are common)
            if any(char.isdigit() for char in subdomain):
                score += 3
            
            # Separator bonus (structured naming)
            if '-' in subdomain or '_' in subdomain:
                score += 2
            
            # Length penalty (very long subdomains are less likely)
            if len(subdomain) > 15:
                score -= 2
            
            scored_perms.append((score, perm))
        
        # Sort by score (descending) and return top results
        scored_perms.sort(key=lambda x: x[0], reverse=True)
        return [perm for _, perm in scored_perms[:max_count]]
    
    def _calculate_strategy_stats(self, permutations: Set[str], target: str) -> Dict[str, Any]:
        """Calculate statistics about generated permutations"""
        
        stats = {
            "total_permutations": len(permutations),
            "target_domain": target,
            "pattern_distribution": {},
            "length_distribution": {},
            "separator_usage": {}
        }
        
        # Analyze patterns
        pattern_counts = {"prefix": 0, "suffix": 0, "number": 0, "compound": 0}
        length_counts = {"short": 0, "medium": 0, "long": 0}
        separator_counts = {"dash": 0, "underscore": 0, "none": 0}
        
        for perm in permutations:
            subdomain = perm.split('.')[0]
            
            # Pattern analysis
            if any(char.isdigit() for char in subdomain):
                pattern_counts["number"] += 1
            if '-' in subdomain or '_' in subdomain:
                pattern_counts["compound"] += 1
            
            # Length analysis
            if len(subdomain) <= 5:
                length_counts["short"] += 1
            elif len(subdomain) <= 10:
                length_counts["medium"] += 1
            else:
                length_counts["long"] += 1
            
            # Separator analysis
            if '-' in subdomain:
                separator_counts["dash"] += 1
            elif '_' in subdomain:
                separator_counts["underscore"] += 1
            else:
                separator_counts["none"] += 1
        
        stats["pattern_distribution"] = pattern_counts
        stats["length_distribution"] = length_counts
        stats["separator_usage"] = separator_counts
        
        return stats
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse output (not used for this tool, but required by base class)"""
        return {"raw": raw_output}