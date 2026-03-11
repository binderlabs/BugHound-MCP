#!/usr/bin/env python3
"""
Workspace Manager for BugHound

Handles creation, organization, and management of scan workspaces.
Each workspace contains organized results for a specific target.
"""

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import uuid

logger = logging.getLogger(__name__)


@dataclass
class WorkspaceMetadata:
    """Metadata for a BugHound workspace"""
    workspace_id: str
    target: str
    description: str
    created_date: str
    status: str  # "active", "completed", "archived"
    scan_count: int = 0
    last_scan_date: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class WorkspaceInfo:
    """Complete workspace information"""
    metadata: WorkspaceMetadata
    workspace_path: Path
    directory_structure: Dict[str, Any]
    scan_history: List[Dict[str, Any]]


class WorkspaceManager:
    """Manages BugHound workspaces for organized scan result storage"""
    
    def __init__(self, base_workspace_dir: str = "workspaces"):
        """
        Initialize workspace manager
        
        Args:
            base_workspace_dir: Base directory for all workspaces
        """
        self.base_dir = Path(base_workspace_dir)
        self.base_dir.mkdir(exist_ok=True)
        
        # Workspace directory structure template
        # Workspace directory structure template (Advanced Hybrid Structure)
        self.workspace_structure = {
            "jobs": {
                "description": "Async background jobs tracking and logs",
                "subdirs": []
            },
            "light": {
                "description": "Fast triage recon data (minutes)",
                "subdirs": [
                    "subdomains", "dns", "hosts", "hosts/screenshots", 
                    "urls", "cloud", "osint", "quick_wins"
                ]
            },
            "deep": {
                "description": "Exhaustive enumeration data (hours)",
                "subdirs": [
                    "subdomains", "dns", "hosts", "hosts/screenshots", 
                    "urls", "secrets", "cloud", "osint", "dirfuzz"
                ]
            },
            "merged": {
                "description": "Aggregated and deduplicated attack surface data",
                "subdirs": []
            },
            "vulnerabilities": {
                "description": "Vulnerability scan results",
                "subdirs": []
            },
            "reports": {
                "description": "Generated final reports",
                "subdirs": []
            }
        }
    
    async def create_workspace(
        self, 
        target: str, 
        description: str = "",
        tags: List[str] = None
    ) -> Tuple[str, Path]:
        """
        Create a new workspace for a target
        
        Args:
            target: Target domain or IP
            description: Optional description of the workspace
            tags: Optional tags for categorization
            
        Returns:
            Tuple of (workspace_id, workspace_path)
        """
        
        try:
            # Generate unique workspace ID and directory name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            workspace_id = str(uuid.uuid4())[:8]
            
            # Clean target name for directory
            clean_target = self._sanitize_target_name(target)
            workspace_dirname = f"{clean_target}_{timestamp}_{workspace_id}"
            workspace_path = self.base_dir / workspace_dirname
            
            # Create workspace directory
            workspace_path.mkdir(exist_ok=True)
            
            # Create directory structure
            await self._create_directory_structure(workspace_path)
            
            # Create metadata
            metadata = WorkspaceMetadata(
                workspace_id=workspace_id,
                target=target,
                description=description or f"Security assessment workspace for {target}",
                created_date=datetime.now().isoformat(),
                status="active",
                tags=tags or []
            )
            
            # Save metadata
            await self._save_metadata(workspace_path, metadata)
            
            # Initialize scan history
            await self._initialize_scan_history(workspace_path)
            
            logger.info(f"Created workspace {workspace_id} for target {target}")
            return workspace_id, workspace_path
            
        except Exception as e:
            logger.error(f"Failed to create workspace for {target}: {e}")
            raise

    async def ensure_workspace(self, target: str) -> Tuple[str, Path]:
        """
        Ensure a workspace exists for the target.
        If it exists, return the most recent one.
        If not, create a new one.
        """
        workspaces = await self.search_workspaces(target)
        if workspaces:
            # Return the most recent matching workspace
            latest = workspaces[0]
            return latest.metadata.workspace_id, latest.workspace_path
        
        # Create new if none found
        return await self.create_workspace(target)

    
    async def list_workspaces(self, status_filter: Optional[str] = None) -> List[WorkspaceInfo]:
        """
        List all workspaces with their metadata
        
        Args:
            status_filter: Optional filter by status ("active", "completed", "archived")
            
        Returns:
            List of WorkspaceInfo objects
        """
        
        workspaces = []
        
        try:
            for workspace_dir in self.base_dir.iterdir():
                if not workspace_dir.is_dir():
                    continue
                
                try:
                    # Load workspace info
                    workspace_info = await self._load_workspace_info(workspace_dir)
                    
                    # Apply status filter
                    if status_filter and workspace_info.metadata.status != status_filter:
                        continue
                    
                    workspaces.append(workspace_info)
                    
                except Exception as e:
                    logger.warning(f"Failed to load workspace {workspace_dir.name}: {e}")
                    continue
            
            # Sort by creation date (newest first)
            workspaces.sort(key=lambda w: w.metadata.created_date, reverse=True)
            
            return workspaces
            
        except Exception as e:
            logger.error(f"Failed to list workspaces: {e}")
            return []
    
    async def get_workspace(self, workspace_id: str) -> Optional[WorkspaceInfo]:
        """
        Get specific workspace by ID
        
        Args:
            workspace_id: Workspace identifier
            
        Returns:
            WorkspaceInfo object or None if not found
        """
        
        try:
            workspaces = await self.list_workspaces()
            
            for workspace in workspaces:
                if workspace.metadata.workspace_id == workspace_id:
                    return workspace
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get workspace {workspace_id}: {e}")
            return None
    
    async def update_workspace_status(self, workspace_id: str, status: str) -> bool:
        """
        Update workspace status
        
        Args:
            workspace_id: Workspace identifier
            status: New status ("active", "completed", "archived")
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                return False
            
            # Update metadata
            workspace.metadata.status = status
            
            # Save updated metadata
            await self._save_metadata(workspace.workspace_path, workspace.metadata)
            
            logger.info(f"Updated workspace {workspace_id} status to {status}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update workspace {workspace_id} status: {e}")
            return False
    
    async def add_scan_record(self, workspace_id: str, scan_info: Dict[str, Any]) -> bool:
        """
        Add a scan record to workspace history
        
        Args:
            workspace_id: Workspace identifier
            scan_info: Scan information dictionary
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                return False
            
            # Load scan history
            history_file = workspace.workspace_path / "scan_history.json"
            scan_history = []
            
            if history_file.exists():
                with open(history_file, 'r') as f:
                    scan_history = json.load(f)
            
            # Add new scan record
            scan_record = {
                "scan_id": str(uuid.uuid4())[:8],
                "timestamp": datetime.now().isoformat(),
                **scan_info
            }
            scan_history.append(scan_record)
            
            # Save updated history
            with open(history_file, 'w') as f:
                json.dump(scan_history, f, indent=2)
            
            # Update workspace metadata
            workspace.metadata.scan_count = len(scan_history)
            workspace.metadata.last_scan_date = scan_record["timestamp"]
            
            await self._save_metadata(workspace.workspace_path, workspace.metadata)
            
            logger.info(f"Added scan record to workspace {workspace_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add scan record to workspace {workspace_id}: {e}")
            return False
    
    async def delete_workspace(self, workspace_id: str) -> bool:
        """
        Delete a workspace and all its contents
        
        Args:
            workspace_id: Workspace identifier
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                return False
            
            # Remove workspace directory
            shutil.rmtree(workspace.workspace_path)
            
            logger.info(f"Deleted workspace {workspace_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete workspace {workspace_id}: {e}")
            return False
    
    def _sanitize_target_name(self, target: str) -> str:
        """Sanitize target name for use in directory names"""
        
        # Replace invalid characters
        sanitized = target.replace(":", "_").replace("/", "_").replace("\\", "_")
        sanitized = sanitized.replace(" ", "_").replace(".", "_")
        
        # Limit length
        if len(sanitized) > 50:
            sanitized = sanitized[:50]
        
        return sanitized
    
    async def _create_directory_structure(self, workspace_path: Path):
        """Create the standard directory structure for a workspace"""
        
        for main_dir, config in self.workspace_structure.items():
            # Create main directory
            main_path = workspace_path / main_dir
            main_path.mkdir(exist_ok=True)
            
            # Create subdirectories
            for subdir in config["subdirs"]:
                subdir_path = main_path / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)
            
            # Create README for the directory
            readme_path = main_path / "README.md"
            with open(readme_path, 'w') as f:
                f.write(f"# {main_dir.title()}\n\n")
                f.write(f"{config['description']}\n\n")
                f.write("## Subdirectories\n\n")
                for subdir in config["subdirs"]:
                    f.write(f"- `{subdir}/` - {subdir.replace('_', ' ').title()}\n")
    
    async def _save_metadata(self, workspace_path: Path, metadata: WorkspaceMetadata):
        """Save workspace metadata to file"""
        
        metadata_file = workspace_path / "metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(asdict(metadata), f, indent=2)
    
    async def _initialize_scan_history(self, workspace_path: Path):
        """Initialize empty scan history file"""
        
        history_file = workspace_path / "scan_history.json"
        with open(history_file, 'w') as f:
            json.dump([], f, indent=2)
    
    async def _load_workspace_info(self, workspace_path: Path) -> WorkspaceInfo:
        """Load complete workspace information"""
        
        # Load metadata
        metadata_file = workspace_path / "metadata.json"
        with open(metadata_file, 'r') as f:
            metadata_dict = json.load(f)
        
        metadata = WorkspaceMetadata(**metadata_dict)
        
        # Load scan history
        history_file = workspace_path / "scan_history.json"
        scan_history = []
        if history_file.exists():
            with open(history_file, 'r') as f:
                scan_history = json.load(f)
        
        # Analyze directory structure
        directory_structure = self._analyze_directory_structure(workspace_path)
        
        return WorkspaceInfo(
            metadata=metadata,
            workspace_path=workspace_path,
            directory_structure=directory_structure,
            scan_history=scan_history
        )
    
    def _analyze_directory_structure(self, workspace_path: Path) -> Dict[str, Any]:
        """Analyze the current directory structure and file counts"""
        
        structure = {}
        
        for main_dir in self.workspace_structure.keys():
            main_path = workspace_path / main_dir
            if main_path.exists():
                structure[main_dir] = {
                    "exists": True,
                    "file_count": len(list(main_path.rglob("*"))),
                    "subdirs": {}
                }
                
                # Check subdirectories
                for subdir in self.workspace_structure[main_dir]["subdirs"]:
                    subdir_path = main_path / subdir
                    if subdir_path.exists():
                        structure[main_dir]["subdirs"][subdir] = {
                            "exists": True,
                            "file_count": len(list(subdir_path.glob("*")))
                        }
                    else:
                        structure[main_dir]["subdirs"][subdir] = {"exists": False}
            else:
                structure[main_dir] = {"exists": False}
        
        return structure
    
    async def save_results(
        self, 
        workspace_id: str, 
        tool_name: str, 
        results: Dict[str, Any], 
        raw_output: str = ""
    ) -> bool:
        """
        Save tool results to the appropriate workspace directory
        
        Args:
            workspace_id: Workspace identifier
            tool_name: Name of the tool that generated results
            results: Parsed results dictionary
            raw_output: Raw tool output string
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                logger.error(f"Workspace {workspace_id} not found")
                return False
            
            # Determine save location based on tool type
            save_path = self._get_save_path(workspace.workspace_path, tool_name)
            if not save_path:
                logger.error(f"Unknown tool type for {tool_name}")
                return False
            
            # Create directory if it doesn't exist
            save_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Generate timestamp for file naming
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save parsed JSON results
            json_file = save_path / f"{tool_name}_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump({
                    "tool": tool_name,
                    "timestamp": timestamp,
                    "target": workspace.metadata.target,
                    "results": results
                }, f, indent=2)
            
            # Save raw output if provided
            if raw_output:
                raw_file = save_path / f"{tool_name}_{timestamp}_raw.txt"
                with open(raw_file, 'w') as f:
                    f.write(raw_output)
            
            # Update scan record
            scan_info = {
                "scan_type": self._get_scan_type(tool_name),
                "tool_name": tool_name,
                "status": "success",
                "results_summary": self._generate_results_summary(tool_name, results),
                "findings_count": self._count_findings(tool_name, results),
                "output_files": {
                    "json": str(json_file.relative_to(workspace.workspace_path)),
                    "raw": str(raw_file.relative_to(workspace.workspace_path)) if raw_output else None
                }
            }
            
            await self.add_scan_record(workspace_id, scan_info)
            
            logger.info(f"Saved {tool_name} results to workspace {workspace_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save results for {tool_name}: {e}")
            return False
    
    def _get_save_path(self, workspace_path: Path, tool_name: str) -> Optional[Path]:
        """Determine the appropriate save path for a tool's results"""
        
        # Map tools to their appropriate directories
        # Map tools to their appropriate directories in new structure
        tool_mappings = {
            # Light Recon
            "subfinder": workspace_path / "light" / "subdomains",
            "assetfinder": workspace_path / "light" / "subdomains",
            "dnsx": workspace_path / "light" / "dns",
            "httpx": workspace_path / "light" / "hosts",
            "wafw00f": workspace_path / "light" / "hosts",
            "gau": workspace_path / "light" / "urls",
            "subjack": workspace_path / "light" / "cloud",
            "whois": workspace_path / "light" / "osint",
            
            # Deep Recon (or legacy mappings mapped to deep)
            "altdns": workspace_path / "deep" / "subdomains", 
            "dns_validator": workspace_path / "deep" / "dns",
            "nmap": workspace_path / "deep" / "hosts",
            "waybackurls": workspace_path / "deep" / "urls",
            "arjun": workspace_path / "deep" / "urls",
            "whatweb": workspace_path / "deep" / "hosts",
            "dirsearch": workspace_path / "deep" / "dirfuzz",
            
            # Vulnerabilities
            "nuclei": workspace_path / "vulnerabilities",
            "dalfox": workspace_path / "vulnerabilities",
            "sqlmap": workspace_path / "vulnerabilities",
            "trufflehog": workspace_path / "vulnerabilities",
            
            # Jobs / AI Analysis
            "ai_analysis": workspace_path / "jobs",
        }
        
        return tool_mappings.get(tool_name)
    
    def _get_scan_type(self, tool_name: str) -> str:
        """Get scan type category for a tool"""
        
        type_mappings = {
            "subfinder": "subdomain_discovery",
            "altdns": "subdomain_enumeration", 
            "dns_validator": "dns_validation",
            "httpx": "live_host_detection",
            "waybackurls": "historical_analysis",
            "nmap": "port_scanning",
            "nuclei": "vulnerability_scanning",
            "ai_analysis": "ai_analysis"
        }
        
        return type_mappings.get(tool_name, "unknown")
    
    def _generate_results_summary(self, tool_name: str, results: Dict[str, Any]) -> str:
        """Generate a summary of results for a tool"""
        
        try:
            if tool_name == "subfinder":
                count = len(results.get("subdomains", []))
                return f"Found {count} subdomains"
                
            elif tool_name == "altdns":
                count = len(results.get("generated_subdomains", []))
                return f"Generated {count} subdomain permutations"
                
            elif tool_name == "dns_validator":
                valid = len(results.get("valid_domains", []))
                return f"Validated {valid} live subdomains"
                
            elif tool_name == "httpx":
                live = len(results.get("live_hosts", []))
                return f"Identified {live} live web services"
                
            elif tool_name == "waybackurls":
                urls = len(results.get("urls", []))
                return f"Found {urls} historical URLs"
                
            elif tool_name == "nmap":
                hosts = len(results.get("hosts", []))
                return f"Scanned {hosts} hosts for open ports"
                
            elif tool_name == "nuclei":
                vulns = len(results.get("vulnerabilities", []))
                return f"Found {vulns} potential vulnerabilities"
                
            elif tool_name == "ai_analysis":
                return "AI analysis completed"
                
            else:
                return f"Results from {tool_name}"
                
        except Exception:
            return f"Results from {tool_name}"
    
    def _count_findings(self, tool_name: str, results: Dict[str, Any]) -> int:
        """Count the number of findings for a tool"""
        
        try:
            if tool_name == "subfinder":
                return len(results.get("subdomains", []))
            elif tool_name == "altdns":
                return len(results.get("generated_subdomains", []))
            elif tool_name == "dns_validator":
                return len(results.get("valid_domains", []))
            elif tool_name == "httpx":
                return len(results.get("live_hosts", []))
            elif tool_name == "waybackurls":
                return len(results.get("urls", []))
            elif tool_name == "nmap":
                # Count total open ports across all hosts
                total_ports = 0
                for host in results.get("hosts", []):
                    total_ports += len(host.get("open_ports", []))
                return total_ports
            elif tool_name == "nuclei":
                return len(results.get("vulnerabilities", []))
            else:
                return 0
                
        except Exception:
            return 0
    
    async def get_all_results(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """
        Get all results from a workspace, organized by tool type
        
        Args:
            workspace_id: Workspace identifier
            
        Returns:
            Dictionary of all results organized by tool type
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                logger.error(f"Workspace {workspace_id} not found")
                return None
            
            all_results = {
                "workspace_id": workspace_id,
                "target": workspace.metadata.target,
                "scan_count": workspace.metadata.scan_count,
                "last_scan": workspace.metadata.last_scan_date,
                "tools": {},
                "summary_stats": {}
            }
            
            # Scan all result directories for tool outputs
            workspace_path = workspace.workspace_path
            result_dirs = [
                ("light/subdomains", ["subfinder", "assetfinder"]),
                ("light/dns", ["dnsx"]),
                ("light/hosts", ["httpx", "wafw00f"]),
                ("light/urls", ["gau"]),
                ("light/cloud", ["subjack"]),
                ("light/osint", ["whois"]),
                ("deep/subdomains", ["altdns"]),
                ("deep/dns", ["dns_validator"]),
                ("deep/hosts", ["nmap", "whatweb"]),
                ("deep/urls", ["waybackurls", "arjun"]),
                ("deep/dirfuzz", ["dirsearch"]),
                ("vulnerabilities", ["nuclei", "dalfox", "sqlmap", "trufflehog"]),
                ("jobs", ["ai_analysis"])
            ]
            
            total_subdomains = 0
            total_live_hosts = 0
            total_vulnerabilities = 0
            
            for dir_path, tool_names in result_dirs:
                full_dir_path = workspace_path / dir_path
                if full_dir_path.exists():
                    
                    for tool_name in tool_names:
                        tool_files = list(full_dir_path.glob(f"{tool_name}_*.json"))
                        if tool_files:
                            # Get the most recent result file for this tool
                            latest_file = max(tool_files, key=lambda f: f.stat().st_mtime)
                            
                            try:
                                with open(latest_file, 'r') as f:
                                    result_data = json.load(f)
                                
                                all_results["tools"][tool_name] = {
                                    "timestamp": result_data.get("timestamp"),
                                    "results": result_data.get("results", {}),
                                    "file_path": str(latest_file.relative_to(workspace_path))
                                }
                                
                                # Update summary statistics
                                results = result_data.get("results", {})
                                if tool_name in ["subfinder", "altdns"]:
                                    subdomains = results.get("subdomains", []) or results.get("generated_subdomains", [])
                                    total_subdomains += len(subdomains)
                                elif tool_name == "httpx":
                                    live_hosts = results.get("live_hosts", [])
                                    total_live_hosts += len(live_hosts)
                                elif tool_name == "nuclei":
                                    vulnerabilities = results.get("vulnerabilities", [])
                                    total_vulnerabilities += len(vulnerabilities)
                                    
                            except Exception as e:
                                logger.warning(f"Failed to read result file {latest_file}: {e}")
            
            # Blend in Deep Recon summary if it exists
            summary_path = workspace.workspace_path / "merged" / "summary.json"
            if summary_path.exists():
                try:
                    with open(summary_path, 'r') as f:
                        summary_data = json.load(f)
                    total_subdomains = max(total_subdomains, summary_data.get("total_domains", 0))
                    total_live_hosts = max(total_live_hosts, summary_data.get("live_hosts", 0))
                    all_results["tools"]["deep_recon"] = {
                        "timestamp": workspace.metadata.last_scan_date or "",
                        "results": {},
                        "file_path": "merged/summary.json"
                    }
                except Exception as e:
                    logger.warning(f"Failed to read deep recon summary: {e}")

            all_results["summary_stats"] = {
                "total_subdomains_found": total_subdomains,
                "total_live_hosts": total_live_hosts,
                "total_vulnerabilities": total_vulnerabilities,
                "tools_executed": len(all_results["tools"])
            }
            
            return all_results
            
        except Exception as e:
            logger.error(f"Failed to get all results for workspace {workspace_id}: {e}")
            return None
    
    async def get_tool_results(self, workspace_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get results for a specific tool from a workspace
        
        Args:
            workspace_id: Workspace identifier
            tool_name: Name of the tool (e.g., 'subfinder', 'httpx', 'nuclei')
            
        Returns:
            Tool results dictionary or None if not found
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                logger.error(f"Workspace {workspace_id} not found")
                return None
            
            # Find the appropriate directory for this tool
            save_path = self._get_save_path(workspace.workspace_path, tool_name)
            if not save_path or not save_path.exists():
                logger.warning(f"No results directory found for tool {tool_name}")
                return None
            
            # Find all result files for this tool
            tool_files = list(save_path.glob(f"{tool_name}_*.json"))
            if not tool_files:
                logger.warning(f"No result files found for tool {tool_name}")
                return None
            
            # Get all results, sorted by timestamp (newest first)
            all_tool_results = []
            
            for result_file in tool_files:
                try:
                    with open(result_file, 'r') as f:
                        result_data = json.load(f)
                    
                    all_tool_results.append({
                        "timestamp": result_data.get("timestamp"),
                        "results": result_data.get("results", {}),
                        "file_path": str(result_file.relative_to(workspace.workspace_path)),
                        "target": result_data.get("target")
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to read result file {result_file}: {e}")
            
            # Sort by timestamp (newest first)
            all_tool_results.sort(key=lambda x: x["timestamp"], reverse=True)
            
            return {
                "tool_name": tool_name,
                "workspace_id": workspace_id,
                "total_executions": len(all_tool_results),
                "latest_execution": all_tool_results[0] if all_tool_results else None,
                "all_executions": all_tool_results
            }
            
        except Exception as e:
            logger.error(f"Failed to get tool results for {tool_name} in workspace {workspace_id}: {e}")
            return None
    
    async def search_workspaces(self, target: str) -> List[WorkspaceInfo]:
        """
        Find all workspaces for a specific target domain
        
        Args:
            target: Target domain to search for
            
        Returns:
            List of WorkspaceInfo objects for matching workspaces
        """
        
        try:
            all_workspaces = await self.list_workspaces()
            
            # Filter workspaces by target (allowing for partial matches)
            matching_workspaces = []
            target_lower = target.lower()
            
            for workspace in all_workspaces:
                workspace_target = workspace.metadata.target.lower()
                
                # Exact match or subdomain match
                if (workspace_target == target_lower or 
                    target_lower in workspace_target or 
                    workspace_target in target_lower):
                    matching_workspaces.append(workspace)
            
            # Sort by creation date (newest first)
            matching_workspaces.sort(key=lambda w: w.metadata.created_date, reverse=True)
            
            return matching_workspaces
            
        except Exception as e:
            logger.error(f"Failed to search workspaces for target {target}: {e}")
            return []
    
    async def get_latest_scan(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Get the most recent scan results for a target
        
        Args:
            target: Target domain
            
        Returns:
            Latest scan results or None if no scans found
        """
        
        try:
            matching_workspaces = await self.search_workspaces(target)
            
            if not matching_workspaces:
                return None
            
            # Get the most recent workspace
            latest_workspace = matching_workspaces[0]
            
            # Get all results from the latest workspace
            all_results = await self.get_all_results(latest_workspace.metadata.workspace_id)
            
            if all_results:
                all_results["workspace_info"] = {
                    "workspace_id": latest_workspace.metadata.workspace_id,
                    "created_date": latest_workspace.metadata.created_date,
                    "description": latest_workspace.metadata.description,
                    "status": latest_workspace.metadata.status
                }
            
            return all_results
            
        except Exception as e:
            logger.error(f"Failed to get latest scan for target {target}: {e}")
            return None
    
    async def get_scan_statistics(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive scan statistics for a workspace
        
        Args:
            workspace_id: Workspace identifier
            
        Returns:
            Dictionary of scan statistics
        """
        
        try:
            workspace = await self.get_workspace(workspace_id)
            if not workspace:
                return None
            
            all_results = await self.get_all_results(workspace_id)
            if not all_results:
                return None
            
            # Calculate detailed statistics
            stats = {
                "workspace_id": workspace_id,
                "target": workspace.metadata.target,
                "scan_duration": self._calculate_scan_duration(workspace),
                "tools_used": list(all_results["tools"].keys()),
                "findings": {
                    "subdomains": all_results["summary_stats"]["total_subdomains_found"],
                    "live_hosts": all_results["summary_stats"]["total_live_hosts"],
                    "vulnerabilities": all_results["summary_stats"]["total_vulnerabilities"]
                },
                "risk_assessment": self._assess_risk_level(all_results),
                "completion_status": self._get_completion_status(workspace, all_results)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get scan statistics for workspace {workspace_id}: {e}")
            return None
    
    def _calculate_scan_duration(self, workspace: WorkspaceInfo) -> Optional[str]:
        """Calculate the duration of the scan"""
        
        try:
            if not workspace.metadata.last_scan_date:
                return None
            
            from datetime import datetime
            created = datetime.fromisoformat(workspace.metadata.created_date)
            last_scan = datetime.fromisoformat(workspace.metadata.last_scan_date)
            
            duration = last_scan - created
            
            if duration.days > 0:
                return f"{duration.days} days, {duration.seconds // 3600} hours"
            elif duration.seconds > 3600:
                return f"{duration.seconds // 3600} hours, {(duration.seconds % 3600) // 60} minutes"
            else:
                return f"{duration.seconds // 60} minutes"
                
        except Exception:
            return None
    
    def _assess_risk_level(self, all_results: Dict[str, Any]) -> str:
        """Assess overall risk level based on findings"""
        
        try:
            vuln_count = all_results["summary_stats"]["total_vulnerabilities"]
            live_hosts = all_results["summary_stats"]["total_live_hosts"]
            
            # Simple risk assessment logic
            if vuln_count > 10:
                return "HIGH"
            elif vuln_count > 5 or live_hosts > 50:
                return "MEDIUM"
            elif vuln_count > 0 or live_hosts > 10:
                return "LOW"
            else:
                return "MINIMAL"
                
        except Exception:
            return "UNKNOWN"
    
    def _get_completion_status(self, workspace: WorkspaceInfo, all_results: Dict[str, Any]) -> str:
        """Get completion status based on tools executed"""
        
        try:
            tools_executed = len(all_results["tools"])
            expected_tools = 3  # Minimum: subfinder, httpx, and one analysis tool
            
            if tools_executed >= expected_tools:
                return "COMPLETE"
            elif tools_executed > 0:
                return "PARTIAL"
            else:
                return "INCOMPLETE"
                
        except Exception:
            return "UNKNOWN"


# Utility functions for external use
async def create_workspace_manager(base_dir: str = "workspaces") -> WorkspaceManager:
    """Create and return a WorkspaceManager instance"""
    return WorkspaceManager(base_dir)


def format_workspace_info(workspace: WorkspaceInfo) -> str:
    """Format workspace information for display"""
    
    metadata = workspace.metadata
    
    output = f"🏠 **Workspace: {metadata.workspace_id}**\n"
    output += f"**Target:** {metadata.target}\n"
    output += f"**Description:** {metadata.description}\n"
    output += f"**Status:** {metadata.status.title()}\n"
    output += f"**Created:** {metadata.created_date[:10]}\n"
    output += f"**Scans:** {metadata.scan_count}\n"
    
    if metadata.last_scan_date:
        output += f"**Last Scan:** {metadata.last_scan_date[:10]}\n"
    
    if metadata.tags:
        output += f"**Tags:** {', '.join(metadata.tags)}\n"
    
    output += f"**Path:** {workspace.workspace_path}\n"
    
    return output