#!/usr/bin/env python3
"""
Nmap Tool for Port Scanning and Service Detection

This tool provides intelligent port scanning with service detection,
focusing on discovering potentially vulnerable services and applications.
"""

import asyncio
import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import tempfile

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class NmapTool(BaseTool):
    """Tool for port scanning and service detection using nmap"""
    
    def __init__(self, timeout: int = 600):
        super().__init__("nmap", timeout)
        
        # Common vulnerable services and their typical ports
        self.vulnerable_services = {
            21: {"service": "ftp", "risks": ["Anonymous access", "Weak credentials"]},
            22: {"service": "ssh", "risks": ["Weak credentials", "Version vulnerabilities"]},
            23: {"service": "telnet", "risks": ["Unencrypted protocol", "Weak credentials"]},
            25: {"service": "smtp", "risks": ["Open relay", "User enumeration"]},
            53: {"service": "dns", "risks": ["Zone transfer", "Cache poisoning"]},
            80: {"service": "http", "risks": ["Web application vulnerabilities"]},
            110: {"service": "pop3", "risks": ["Weak credentials", "Unencrypted"]},
            111: {"service": "rpcbind", "risks": ["Information disclosure"]},
            135: {"service": "msrpc", "risks": ["Windows enumeration"]},
            139: {"service": "netbios", "risks": ["SMB enumeration"]},
            143: {"service": "imap", "risks": ["Weak credentials", "Unencrypted"]},
            443: {"service": "https", "risks": ["SSL/TLS vulnerabilities", "Web app issues"]},
            445: {"service": "smb", "risks": ["Share enumeration", "SMB vulnerabilities"]},
            993: {"service": "imaps", "risks": ["SSL/TLS issues"]},
            995: {"service": "pop3s", "risks": ["SSL/TLS issues"]},
            1433: {"service": "mssql", "risks": ["SQL injection", "Weak credentials"]},
            1521: {"service": "oracle", "risks": ["Default accounts", "SQL injection"]},
            3306: {"service": "mysql", "risks": ["Weak credentials", "SQL injection"]},
            3389: {"service": "rdp", "risks": ["Weak credentials", "RDP vulnerabilities"]},
            5432: {"service": "postgresql", "risks": ["Weak credentials", "SQL injection"]},
            5900: {"service": "vnc", "risks": ["Weak/no authentication"]},
            6379: {"service": "redis", "risks": ["Unauthenticated access"]},
            8080: {"service": "http-alt", "risks": ["Web application vulnerabilities"]},
            8443: {"service": "https-alt", "risks": ["Web application vulnerabilities"]},
            9200: {"service": "elasticsearch", "risks": ["Unauthenticated access"]},
            27017: {"service": "mongodb", "risks": ["Unauthenticated access"]}
        }
        
        # Port sets for different scan types
        self.port_sets = {
            "top100": "1-1024",
            "top1000": "--top-ports 1000", 
            "common": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
            "web": "80,443,8080,8443,8000,8888,9000,9090",
            "database": "1433,1521,3306,5432,6379,9200,27017"
        }
    
    async def execute(self, targets: List[str], options: Dict[str, Any] = None) -> ToolResult:
        """
        Execute nmap scan on targets
        
        Args:
            targets: List of IP addresses or hostnames to scan
            options: Scan options (ports, scan_type, etc.)
            
        Returns:
            ToolResult with discovered services and analysis
        """
        
        if options is None:
            options = {}
        
        try:
            if not targets:
                return ToolResult(
                    success=False,
                    error="No targets provided for scanning"
                )
            
            # Validate targets
            valid_targets = self._validate_targets(targets)
            if not valid_targets:
                return ToolResult(
                    success=False,
                    error="No valid targets after validation"
                )
            
            logger.info(f"Starting nmap scan for {len(valid_targets)} targets")
            
            # Build and execute nmap command
            scan_results = await self._execute_nmap_scan(valid_targets, options)
            
            if not scan_results:
                return ToolResult(
                    success=True,
                    data={
                        "hosts": [],
                        "services": [],
                        "vulnerabilities": [],
                        "statistics": {
                            "hosts_scanned": len(valid_targets),
                            "hosts_up": 0,
                            "total_ports": 0,
                            "open_ports": 0,
                            "services_detected": 0
                        }
                    }
                )
            
            # Process and analyze results
            processed_data = await self._process_scan_results(scan_results, options)
            
            logger.info(f"Nmap scan completed: {processed_data['statistics']['hosts_up']} hosts up, "
                       f"{processed_data['statistics']['open_ports']} open ports found")
            
            return ToolResult(success=True, data=processed_data, raw_output=scan_results)
            
        except Exception as e:
            error_msg = f"Nmap scan failed: {str(e)}"
            logger.error(error_msg)
            return ToolResult(success=False, error=error_msg)
    
    async def _execute_nmap_scan(self, targets: List[str], options: Dict[str, Any]) -> Optional[str]:
        """Execute nmap scan and return XML output"""
        
        try:
            # Create temporary file for XML output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
                xml_output_file = tmp_file.name
            
            # Build nmap command
            cmd = self._build_nmap_command(targets, xml_output_file, options)
            
            logger.info(f"Executing nmap: {' '.join(cmd[:5])}... (truncated)")
            logger.debug(f"Full nmap command: {' '.join(cmd)}")
            
            # Execute nmap
            await self._run_command(cmd)
            
            # Read XML output
            try:
                with open(xml_output_file, 'r') as f:
                    xml_content = f.read()
                
                # Clean up temp file
                Path(xml_output_file).unlink()
                
                return xml_content
                
            except Exception as e:
                logger.error(f"Failed to read nmap XML output: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
            raise
    
    def _build_nmap_command(self, targets: List[str], xml_output: str, options: Dict[str, Any]) -> List[str]:
        """Build nmap command with appropriate options"""
        
        cmd = ["nmap"]
        
        # Output format
        cmd.extend(["-oX", xml_output])
        
        # Scan type
        scan_type = options.get("scan_type", "syn")
        if scan_type == "syn":
            cmd.append("-sS")  # SYN scan
        elif scan_type == "connect":
            cmd.append("-sT")  # Connect scan
        elif scan_type == "udp":
            cmd.append("-sU")  # UDP scan
        elif scan_type == "version":
            cmd.extend(["-sS", "-sV"])  # Version detection
        
        # Service detection
        if options.get("service_detection", True):
            cmd.append("-sV")
        
        # OS detection
        if options.get("os_detection", False):
            cmd.append("-O")
        
        # Script scanning
        if options.get("script_scan", False):
            cmd.extend(["--script", "default"])
        
        # Timing
        timing = options.get("timing", "3")
        cmd.extend(["-T", str(timing)])
        
        # Port specification
        ports = options.get("ports", "common")
        if ports in self.port_sets:
            if ports == "top1000":
                cmd.append("--top-ports")
                cmd.append("1000")
            else:
                port_range = self.port_sets[ports]
                if port_range != "1-1024":  # Don't add -p for top1000
                    cmd.extend(["-p", port_range])
        else:
            # Custom port range
            cmd.extend(["-p", ports])
        
        # Skip host discovery for single hosts
        if len(targets) == 1:
            cmd.append("-Pn")
        
        # Rate limiting
        max_rate = options.get("max_rate", 1000)
        cmd.extend(["--max-rate", str(max_rate)])
        
        # Timeout
        timeout = options.get("host_timeout", "300s")
        cmd.extend(["--host-timeout", timeout])
        
        # Add targets
        cmd.extend(targets)
        
        return cmd
    
    async def _process_scan_results(self, xml_content: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process nmap XML output and analyze results"""
        
        try:
            root = ET.fromstring(xml_content)
            
            hosts = []
            all_services = []
            vulnerabilities = []
            
            hosts_up = 0
            total_ports = 0
            open_ports = 0
            services_detected = 0
            
            # Process each host
            for host_elem in root.findall('host'):
                host_data = self._process_host(host_elem)
                
                if host_data:
                    hosts.append(host_data)
                    
                    if host_data["state"] == "up":
                        hosts_up += 1
                    
                    # Collect services and analyze for vulnerabilities
                    for service in host_data["services"]:
                        all_services.append(service)
                        total_ports += 1
                        
                        if service["state"] == "open":
                            open_ports += 1
                            
                            if service.get("service"):
                                services_detected += 1
                            
                            # Analyze for potential vulnerabilities
                            vuln_analysis = self._analyze_service_vulnerabilities(service, host_data["ip"])
                            if vuln_analysis:
                                vulnerabilities.extend(vuln_analysis)
            
            # Sort results by risk
            vulnerabilities.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            all_services.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            
            return {
                "hosts": hosts,
                "services": all_services[:50],  # Limit services shown
                "vulnerabilities": vulnerabilities[:20],  # Top 20 vulnerabilities
                "statistics": {
                    "hosts_scanned": len(root.findall('host')),
                    "hosts_up": hosts_up,
                    "total_ports": total_ports,
                    "open_ports": open_ports,
                    "services_detected": services_detected
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to process nmap XML: {e}")
            raise
    
    def _process_host(self, host_elem) -> Optional[Dict[str, Any]]:
        """Process individual host from nmap XML"""
        
        try:
            # Get host address
            address_elem = host_elem.find('address')
            if address_elem is None:
                return None
            
            ip = address_elem.get('addr')
            
            # Get host state
            status_elem = host_elem.find('status')
            state = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Get hostname if available
            hostnames = []
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                for hostname_elem in hostnames_elem.findall('hostname'):
                    name = hostname_elem.get('name')
                    if name:
                        hostnames.append(name)
            
            # Process ports
            services = []
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    service_data = self._process_port(port_elem, ip)
                    if service_data:
                        services.append(service_data)
            
            # Get OS information if available
            os_info = None
            os_elem = host_elem.find('os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('osmatch')
                if osmatch_elem is not None:
                    os_info = {
                        "name": osmatch_elem.get('name'),
                        "accuracy": osmatch_elem.get('accuracy')
                    }
            
            return {
                "ip": ip,
                "hostnames": hostnames,
                "state": state,
                "services": services,
                "os_info": os_info
            }
            
        except Exception as e:
            logger.error(f"Failed to process host: {e}")
            return None
    
    def _process_port(self, port_elem, host_ip: str) -> Optional[Dict[str, Any]]:
        """Process individual port from nmap XML"""
        
        try:
            port_id = port_elem.get('portid')
            protocol = port_elem.get('protocol')
            
            # Get port state
            state_elem = port_elem.find('state')
            state = state_elem.get('state') if state_elem is not None else 'unknown'
            
            # Get service information
            service_elem = port_elem.find('service')
            service_name = None
            service_version = None
            service_product = None
            
            if service_elem is not None:
                service_name = service_elem.get('name')
                service_version = service_elem.get('version')
                service_product = service_elem.get('product')
            
            # Calculate risk score
            risk_score = self._calculate_service_risk_score(
                int(port_id), service_name, state
            )
            
            return {
                "host": host_ip,
                "port": int(port_id),
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": service_version,
                "product": service_product,
                "risk_score": risk_score
            }
            
        except Exception as e:
            logger.error(f"Failed to process port: {e}")
            return None
    
    def _analyze_service_vulnerabilities(self, service: Dict[str, Any], host_ip: str) -> List[Dict[str, Any]]:
        """Analyze service for potential vulnerabilities"""
        
        vulnerabilities = []
        port = service["port"]
        service_name = service.get("service", "")
        version = service.get("version", "")
        
        # Check against known vulnerable services
        if port in self.vulnerable_services:
            vuln_info = self.vulnerable_services[port]
            
            for risk in vuln_info["risks"]:
                vulnerability = {
                    "host": host_ip,
                    "port": port,
                    "service": service_name or vuln_info["service"],
                    "vulnerability": risk,
                    "risk_score": self._calculate_vulnerability_risk_score(port, risk, version),
                    "recommendations": self._get_vulnerability_recommendations(port, risk)
                }
                vulnerabilities.append(vulnerability)
        
        # Version-specific vulnerabilities
        if version:
            version_vulns = self._check_version_vulnerabilities(service_name, version)
            for vuln in version_vulns:
                vuln["host"] = host_ip
                vuln["port"] = port
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_service_risk_score(self, port: int, service: Optional[str], state: str) -> int:
        """Calculate risk score for a service"""
        
        if state != "open":
            return 0
        
        score = 1  # Base score for open port
        
        # High-risk ports
        if port in [21, 23, 25, 53, 135, 139, 445, 1433, 3389, 5900]:
            score += 4
        
        # Medium-risk ports
        elif port in [22, 80, 110, 143, 443, 993, 995]:
            score += 2
        
        # Database ports
        elif port in [1521, 3306, 5432, 6379, 9200, 27017]:
            score += 3
        
        # Uncommon high ports might be interesting
        elif port > 8000:
            score += 1
        
        return min(score, 10)  # Cap at 10
    
    def _calculate_vulnerability_risk_score(self, port: int, risk: str, version: Optional[str]) -> int:
        """Calculate risk score for a specific vulnerability"""
        
        base_score = 5
        
        # High-impact vulnerabilities
        if any(term in risk.lower() for term in ["authentication", "credentials", "access"]):
            base_score += 3
        
        # Medium-impact vulnerabilities  
        elif any(term in risk.lower() for term in ["enumeration", "disclosure"]):
            base_score += 2
        
        # Critical services
        if port in [22, 3389, 445, 1433, 3306, 5432]:
            base_score += 2
        
        return min(base_score, 10)
    
    def _check_version_vulnerabilities(self, service: Optional[str], version: str) -> List[Dict[str, Any]]:
        """Check for known version-specific vulnerabilities"""
        
        vulnerabilities = []
        
        if not service or not version:
            return vulnerabilities
        
        # Simple version vulnerability checks
        # In a real implementation, this would query a CVE database
        
        version_lower = version.lower()
        service_lower = service.lower()
        
        # Example checks for common services
        if "ssh" in service_lower and "openssh" in version_lower:
            if any(ver in version_lower for ver in ["7.0", "7.1", "7.2"]):
                vulnerabilities.append({
                    "vulnerability": "OpenSSH version vulnerability",
                    "risk_score": 6,
                    "recommendations": ["Update to latest OpenSSH version"]
                })
        
        return vulnerabilities
    
    def _get_vulnerability_recommendations(self, port: int, risk: str) -> List[str]:
        """Get recommendations for addressing vulnerabilities"""
        
        recommendations = []
        
        if "weak credentials" in risk.lower():
            recommendations.extend([
                "Implement strong password policy",
                "Enable two-factor authentication",
                "Use key-based authentication where possible"
            ])
        
        elif "anonymous access" in risk.lower():
            recommendations.append("Disable anonymous access")
        
        elif "enumeration" in risk.lower():
            recommendations.extend([
                "Restrict access to authorized users only",
                "Implement network segmentation"
            ])
        
        elif "unencrypted" in risk.lower():
            recommendations.extend([
                "Enable encryption/TLS",
                "Disable unencrypted protocols"
            ])
        
        # Port-specific recommendations
        if port == 21:  # FTP
            recommendations.append("Consider using SFTP instead of FTP")
        elif port == 23:  # Telnet
            recommendations.append("Replace Telnet with SSH")
        elif port == 3389:  # RDP
            recommendations.extend([
                "Enable Network Level Authentication",
                "Use VPN for remote access"
            ])
        
        return recommendations
    
    def _validate_targets(self, targets: List[str]) -> List[str]:
        """Validate and filter targets"""
        
        valid_targets = []
        
        for target in targets:
            # Basic validation
            if not target or len(target) < 3:
                continue
            
            # Allow IPs and hostnames
            if re.match(r'^[\w\.-]+$', target):
                valid_targets.append(target)
            else:
                logger.warning(f"Invalid target skipped: {target}")
        
        return valid_targets
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse nmap raw output (required by base class)"""
        
        if not raw_output:
            return {
                "hosts": [],
                "services": [],
                "vulnerabilities": [],
                "statistics": {
                    "hosts_scanned": 0,
                    "hosts_up": 0,
                    "open_ports": 0,
                    "services_detected": 0
                }
            }
        
        # Basic parsing of text output - this is a simplified version
        # In practice, XML parsing would be much more robust
        hosts = []
        services = []
        open_ports = 0
        
        lines = raw_output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Host discovery
            if "Nmap scan report for" in line:
                current_host = line.split("for ")[-1].strip()
                if current_host:
                    hosts.append({"ip": current_host, "status": "up", "open_ports": []})
            
            # Port detection
            elif "/tcp" in line or "/udp" in line and current_host:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else ""
                    
                    if state == "open":
                        open_ports += 1
                        port_num = port_info.split('/')[0]
                        protocol = port_info.split('/')[1] if '/' in port_info else 'tcp'
                        
                        service_info = {
                            "host": current_host,
                            "port": int(port_num) if port_num.isdigit() else 0,
                            "protocol": protocol,
                            "state": state,
                            "service": service,
                            "risk_score": 3  # Default medium risk
                        }
                        services.append(service_info)
                        
                        if hosts:
                            hosts[-1]["open_ports"].append(service_info)
        
        return {
            "hosts": hosts,
            "services": services,
            "vulnerabilities": [],
            "statistics": {
                "hosts_scanned": len(hosts),
                "hosts_up": len([h for h in hosts if h["status"] == "up"]),
                "open_ports": open_ports,
                "services_detected": len(services)
            }
        }
    
    def format_results(self, result: ToolResult) -> str:
        """Format nmap results for display"""
        
        if not result.success:
            return f"❌ Nmap scan failed: {result.error}"
        
        data = result.data
        stats = data["statistics"]
        
        output = f"🔍 **Port Scan Results**\n\n"
        output += f"**Statistics:**\n"
        output += f"• Hosts scanned: {stats['hosts_scanned']}\n"
        output += f"• Hosts up: {stats['hosts_up']}\n"
        output += f"• Open ports: {stats['open_ports']}\n"
        output += f"• Services detected: {stats['services_detected']}\n\n"
        
        # Show high-risk services
        high_risk_services = [s for s in data["services"] if s.get("risk_score", 0) >= 5]
        if high_risk_services:
            output += f"🚨 **High-Risk Services ({len(high_risk_services)})**\n"
            for service in high_risk_services[:10]:
                risk_emoji = "🔥" if service["risk_score"] >= 8 else "⚡"
                output += f"{risk_emoji} {service['host']}:{service['port']} - {service.get('service', 'unknown')} (Risk: {service['risk_score']})\n"
                if service.get("version"):
                    output += f"   📋 Version: {service['version']}\n"
            output += "\n"
        
        # Show vulnerabilities
        if data["vulnerabilities"]:
            output += f"⚠️ **Potential Vulnerabilities ({len(data['vulnerabilities'])})**\n"
            for vuln in data["vulnerabilities"][:8]:
                risk_emoji = "🔥" if vuln["risk_score"] >= 8 else "⚡" if vuln["risk_score"] >= 6 else "📍"
                output += f"{risk_emoji} {vuln['host']}:{vuln['port']} - {vuln['vulnerability']} (Risk: {vuln['risk_score']})\n"
                if vuln.get("recommendations"):
                    output += f"   💡 {vuln['recommendations'][0]}\n"
            output += "\n"
        
        if not high_risk_services and not data["vulnerabilities"]:
            output += "✅ No high-risk services or obvious vulnerabilities detected.\n"
        
        return output