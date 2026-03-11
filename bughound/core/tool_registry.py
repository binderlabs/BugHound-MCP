from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ToolSpec:
    """Specification for a BugHound tool"""
    name: str
    stage: str # recon | historical | light_scan | deep_scan | validation | reporting
    risk: str # safe | medium | intrusive
    default_enabled: bool
    description: str

def get_all_tools() -> List[ToolSpec]:
    """Get registry of all supported tools"""
    return [
        # Reconnaissance
        ToolSpec("subfinder", "recon", "safe", True, "Passive subdomain discovery"),
        ToolSpec("altdns", "recon", "safe", True, "Subdomain permutation generation"),
        ToolSpec("crtsh", "recon", "safe", True, "Certificate Transparency logs"),
        ToolSpec("waybackurls", "historical", "safe", True, "Historical URL discovery"),
        ToolSpec("gau", "historical", "safe", True, "Fetch all URLs (AlienVault, Wayback, etc)"),
        
        # Network / Web Analysis
        ToolSpec("httpx", "light_scan", "safe", True, "Live host and technology fingerprinting"),
        ToolSpec("subjack", "light_scan", "safe", False, "Subdomain takeover detection"),
        
        # Vulnerability Scanning (Light/Medium)
        ToolSpec("nuclei", "light_scan", "medium", True, "Template-based vulnerability scanner"),
        ToolSpec("trufflehog", "light_scan", "safe", False, "Secrets filtering in responses"),
        
        # Active/Intrusive Scanning (Deep)
        ToolSpec("nmap", "deep_scan", "intrusive", False, "Port scanning and service detection"),
        ToolSpec("ffuf", "deep_scan", "intrusive", False, "Directory and parameter brute-forcing"),
        ToolSpec("wpscan", "deep_scan", "intrusive", False, "WordPress vulnerability scanner"),
        
        # Exploitation / Verification (Validation)
        ToolSpec("dalfox", "validation", "intrusive", False, "XSS scanning and verification"),
        ToolSpec("sqlmap", "validation", "intrusive", False, "SQL Injection detection and exploitation"),
        ToolSpec("interactsh", "validation", "safe", False, "OOB interaction gathering (SSRF)")
    ]
