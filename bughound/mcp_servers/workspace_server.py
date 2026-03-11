#!/usr/bin/env python3
"""
BugHound Workspace Management MCP Server

Provides workspace creation, listing, and management capabilities
through the Model Context Protocol (MCP).
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from ..core.workspace_manager import WorkspaceManager, format_workspace_info
from ..core.change_detector import ChangeDetector, format_change_report, format_change_list, ChangeType
from ..core.report_generator import ReportGenerator, ReportType, ReportFormat
from ..core.scan_plan import ScanPlan
from ..core.decision_engine import DecisionEngine
from ..core.policy_engine import PolicyEngine
from ..core.scan_modes import ScanModes
from ..core.tool_registry import get_all_tools

# Configure logging — stderr only (stdout is reserved for JSON-RPC stdio transport)
import sys as _sys
logging.basicConfig(level=logging.WARNING, stream=_sys.stderr)
logger = logging.getLogger(__name__)

class BugHoundWorkspaceServer:
    """MCP Server for workspace management operations"""
    
    def __init__(self):
        self.server = Server("bughound-workspace")
        self.workspace_manager = WorkspaceManager()
        
        # Initialize change detector and report generator (no external AI needed)
        self.change_detector = ChangeDetector(self.workspace_manager)
        self.report_generator = ReportGenerator(self.workspace_manager)
        logger.info("Change detector and report generator initialized (pure MCP)")
        
        # Initialize evidence collector
        try:
            from ..core.evidence_collector import EvidenceCollector
            self.evidence_collector = EvidenceCollector(self.workspace_manager)
            logger.info("Evidence collector initialized")
        except ImportError:
            logger.warning("Evidence collector not available")
            self.evidence_collector = None
        
        # Initialize workspace dashboard
        try:
            from ..core.workspace_dashboard import WorkspaceDashboard
            self.dashboard = WorkspaceDashboard(
                workspace_manager=self.workspace_manager,
                change_detector=self.change_detector
            )
            logger.info("Workspace dashboard initialized (pure MCP)")
        except ImportError:
            logger.warning("Workspace dashboard not available")
            self.dashboard = None
        
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """List available workspace tools"""
            
            return [
                types.Tool(
                    name="create_workspace",
                    description="Create a new workspace for a security assessment target",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain or IP address"
                            },
                            "description": {
                                "type": "string",
                                "description": "Optional description of the workspace"
                            },
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Optional tags for categorization"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                types.Tool(
                    name="list_workspaces",
                    description="List all workspaces with optional status filtering",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "status_filter": {
                                "type": "string",
                                "enum": ["active", "completed", "archived"],
                                "description": "Filter workspaces by status"
                            }
                        },
                        "required": []
                    }
                ),
                types.Tool(
                    name="get_workspace",
                    description="Get detailed information about a specific workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier"
                            }
                        },
                        "required": ["workspace_id"]
                    }
                ),
                types.Tool(
                    name="update_workspace_status",
                    description="Update the status of a workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier"
                            },
                            "status": {
                                "type": "string",
                                "enum": ["active", "completed", "archived"],
                                "description": "New workspace status"
                            }
                        },
                        "required": ["workspace_id", "status"]
                    }
                ),
                types.Tool(
                    name="add_scan_record",
                    description="Add a scan record to workspace history",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier"
                            },
                            "scan_type": {
                                "type": "string",
                                "description": "Type of scan performed"
                            },
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the tool used"
                            },
                            "status": {
                                "type": "string",
                                "enum": ["success", "failed", "partial"],
                                "description": "Scan status"
                            },
                            "results_summary": {
                                "type": "string",
                                "description": "Brief summary of scan results"
                            },
                            "findings_count": {
                                "type": "integer",
                                "description": "Number of findings discovered"
                            }
                        },
                        "required": ["workspace_id", "scan_type", "tool_name", "status"]
                    }
                ),
                types.Tool(
                    name="delete_workspace",
                    description="Delete a workspace and all its contents (use with caution)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier"
                            },
                            "confirm": {
                                "type": "boolean",
                                "description": "Confirmation flag (must be true)"
                            }
                        },
                        "required": ["workspace_id", "confirm"]
                    }
                ),
                types.Tool(
                    name="get_workspace_results",
                    description="Retrieve all results from a specific workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier"
                            },
                            "include_raw": {
                                "type": "boolean",
                                "description": "Include raw result data (default: false, shows summary)",
                                "default": False
                            }
                        },
                        "required": ["workspace_id"]
                    }
                ),
                types.Tool(
                    name="view_dashboard",
                    description="Show comprehensive workspace dashboard with visual summaries. DO NOT run this immediately after creating a workspace; ONLY run this after reconnaissance or scanning is complete.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "ID of workspace to view dashboard for"
                            },
                            "include_ai": {
                                "type": "boolean",
                                "description": "Include AI-generated insights and recommendations",
                                "default": True
                            },
                            "show_visuals": {
                                "type": "boolean",
                                "description": "Include ASCII visual charts and graphs",
                                "default": True
                            }
                        },
                        "required": ["workspace_id"]
                    }
                ),
                types.Tool(
                    name="generate_report",
                    description="Generate professional security reports from workspace data",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "ID of workspace to generate report from"
                            },
                            "report_type": {
                                "type": "string",
                                "enum": ["executive_summary", "technical_report", "bug_bounty_submission", "change_report"],
                                "description": "Type of report to generate",
                                "default": "technical_report"
                            },
                            "format": {
                                "type": "string",
                                "enum": ["markdown", "html", "json"],
                                "description": "Output format for the report",
                                "default": "markdown"
                            },
                            "save_to_workspace": {
                                "type": "boolean",
                                "description": "Save report to workspace reports directory",
                                "default": True
                            },
                            "options": {
                                "type": "object",
                                "description": "Additional options for report generation",
                                "properties": {
                                    "include_changes": {
                                        "type": "boolean",
                                        "description": "Include change analysis in report"
                                    },
                                    "platform": {
                                        "type": "string",
                                        "enum": ["hackerone", "bugcrowd", "generic"],
                                        "description": "Bug bounty platform formatting"
                                    }
                                }
                            }
                        },
                        "required": ["workspace_id"]
                    }
                ),
                types.Tool(
                    name="export_findings",
                    description="Export specific vulnerabilities and findings from workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "ID of workspace to export from"
                            },
                            "severity_filter": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"]
                                },
                                "description": "Filter findings by severity levels",
                                "default": ["critical", "high"]
                            },
                            "format": {
                                "type": "string",
                                "enum": ["json", "csv", "markdown"],
                                "description": "Export format",
                                "default": "json"
                            },
                            "include_evidence": {
                                "type": "boolean",
                                "description": "Include technical evidence in export",
                                "default": True
                            }
                        },
                        "required": ["workspace_id"]
                    }
                ),
                types.Tool(
                    name="export_workspace",
                    description="Export a workspace as a portable package for sharing or backup",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "Workspace identifier to export"
                            },
                            "export_format": {
                                "type": "string",
                                "description": "Export format",
                                "enum": ["zip", "tar.gz", "tar.bz2"],
                                "default": "zip"
                            },
                            "include_evidence": {
                                "type": "boolean",
                                "description": "Include evidence files in export",
                                "default": True
                            },
                            "include_raw_data": {
                                "type": "boolean",
                                "description": "Include raw tool outputs",
                                "default": False
                            },
                            "export_path": {
                                "type": "string",
                                "description": "Custom export path (default: workspaces/exports/)"
                            }
                        },
                        "required": ["workspace_id"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: Dict[str, Any]
        ) -> List[types.TextContent]:
            """Handle tool execution requests"""
            
            logger.info(f"Executing workspace tool: {name}")
            
            try:
                if name == "create_workspace":
                    return await self._handle_create_workspace(arguments)
                
                elif name == "list_workspaces":
                    return await self._handle_list_workspaces(arguments)
                
                elif name == "get_workspace":
                    return await self._handle_get_workspace(arguments)
                
                elif name == "update_workspace_status":
                    return await self._handle_update_workspace_status(arguments)
                
                elif name == "add_scan_record":
                    return await self._handle_add_scan_record(arguments)
                
                elif name == "delete_workspace":
                    return await self._handle_delete_workspace(arguments)
                
                elif name == "get_workspace_results":
                    return await self._handle_get_workspace_results(arguments)
                
                elif name == "get_tool_results":
                    return await self._handle_get_tool_results(arguments)
                
                elif name == "get_latest_scan":
                    return await self._handle_get_latest_scan(arguments)
                
                elif name == "view_scan_history":
                    return await self._handle_view_scan_history(arguments)
                
                elif name == "search_workspaces":
                    return await self._handle_search_workspaces(arguments)
                
                elif name == "compare_scans":
                    return await self._handle_compare_scans(arguments)
                
                elif name == "monitor_target":
                    return await self._handle_monitor_target(arguments)
                
                elif name == "get_new_findings":
                    return await self._handle_get_new_findings(arguments)
                
                elif name == "generate_report":
                    return await self._handle_generate_report(arguments)
                
                elif name == "export_findings":
                    return await self._handle_export_findings(arguments)
                
                elif name == "create_submission":
                    return await self._handle_create_submission(arguments)
                
                elif name == "collect_evidence":
                    return await self._handle_collect_evidence(arguments)
                
                elif name == "list_evidence":
                    return await self._handle_list_evidence(arguments)
                
                elif name == "get_decision_log":
                    return await self._handle_get_decision_log(arguments)
                
                elif name == "simulate_scan_plan":
                    return await self._handle_simulate_scan_plan(arguments)
                
                elif name == "generate_scan_plan":
                    return await self._handle_generate_scan_plan(arguments)
                
                elif name == "analyze_surface":
                    return await self._handle_analyze_surface(arguments)
                
                elif name == "get_policy_profile":
                    return await self._handle_get_policy_profile(arguments)
                
                elif name == "validate_scope":
                    return await self._handle_validate_scope(arguments)
                
                elif name == "list_suppressed_findings":
                    return await self._handle_list_suppressed_findings(arguments)
                
                elif name == "get_capabilities":
                    return await self._handle_get_capabilities(arguments)
                
                elif name == "attach_evidence":
                    return await self._handle_attach_evidence(arguments)
                
                elif name == "view_dashboard":
                    return await self._handle_view_dashboard(arguments)
                
                elif name == "get_statistics":
                    return await self._handle_get_statistics(arguments)
                
                elif name == "generate_summary":
                    return await self._handle_generate_summary(arguments)
                
                elif name == "archive_workspace":
                    return await self._handle_archive_workspace(arguments)
                
                elif name == "export_workspace":
                    return await self._handle_export_workspace(arguments)
                
                elif name == "clean_workspace":
                    return await self._handle_clean_workspace(arguments)
                
                elif name == "backup_workspaces":
                    return await self._handle_backup_workspaces(arguments)
                
                elif name == "configure_workspace":
                    return await self._handle_configure_workspace(arguments)
                
                else:
                    return [types.TextContent(
                        type="text",
                        text=f"❌ Unknown tool: {name}"
                    )]
                    
            except Exception as e:
                logger.error(f"Error executing tool {name}: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"❌ Error executing {name}: {str(e)}"
                )]
    
    async def _handle_create_workspace(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle workspace creation"""
        
        target = arguments["target"]
        description = arguments.get("description", "")
        tags = arguments.get("tags", [])
        
        try:
            workspace_id, workspace_path = await self.workspace_manager.create_workspace(
                target=target,
                description=description,
                tags=tags
            )
            
            response = f"✅ **Workspace Created Successfully**\n\n"
            response += f"**Workspace ID:** {workspace_id}\n"
            response += f"**Target:** {target}\n"
            response += f"**Path:** {workspace_path}\n"
            response += f"**Description:** {description or f'Security assessment workspace for {target}'}\n"
            
            if tags:
                response += f"**Tags:** {', '.join(tags)}\n"
            
            response += f"\n📁 **Directory Structure Created:**\n"
            for main_dir, config in self.workspace_manager.workspace_structure.items():
                response += f"- `{main_dir}/` - {config['description']}\n"
                for subdir in config['subdirs']:
                    response += f"  - `{subdir}/`\n"
            
            response += f"\n🚀 **Next Steps:**\n"
            response += f"- Use reconnaissance tools to scan the target\n"
            response += f"- Results will be automatically organized in this workspace\n"
            response += f"- Use `get_workspace {workspace_id}` to check progress\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to create workspace: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to create workspace for {target}: {str(e)}"
            )]
    
    async def _handle_list_workspaces(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle workspace listing"""
        
        status_filter = arguments.get("status_filter")
        
        try:
            workspaces = await self.workspace_manager.list_workspaces(status_filter)
            
            if not workspaces:
                if status_filter:
                    response = f"📂 No workspaces found with status: {status_filter}"
                else:
                    response = "📂 No workspaces found. Create your first workspace with `create_workspace`."
                
                return [types.TextContent(type="text", text=response)]
            
            response = f"📂 **BugHound Workspaces**"
            if status_filter:
                response += f" (Status: {status_filter})"
            response += f"\n\nFound {len(workspaces)} workspace(s):\n\n"
            
            for i, workspace in enumerate(workspaces, 1):
                metadata = workspace.metadata
                
                # Status emoji
                status_emoji = {"active": "🟢", "completed": "✅", "archived": "📦"}.get(metadata.status, "❓")
                
                response += f"**{i}. {metadata.target}** {status_emoji}\n"
                response += f"   ID: `{metadata.workspace_id}`\n"
                response += f"   Created: {metadata.created_date[:10]}\n"
                response += f"   Scans: {metadata.scan_count}\n"
                
                if metadata.last_scan_date:
                    response += f"   Last Scan: {metadata.last_scan_date[:10]}\n"
                
                if metadata.tags:
                    response += f"   Tags: {', '.join(metadata.tags)}\n"
                
                response += "\n"
            
            response += "💡 Use `get_workspace <id>` for detailed information about a specific workspace."
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to list workspaces: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to list workspaces: {str(e)}"
            )]
    
    async def _handle_get_workspace(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle getting specific workspace information"""
        
        workspace_id = arguments["workspace_id"]
        
        try:
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            
            if not workspace:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Workspace not found: {workspace_id}"
                )]
            
            # Use the utility function to format workspace info
            response = format_workspace_info(workspace)
            
            # Add directory structure analysis
            response += "\n📁 **Directory Structure:**\n"
            for main_dir, info in workspace.directory_structure.items():
                if info["exists"]:
                    response += f"- `{main_dir}/` ({info['file_count']} files)\n"
                    for subdir, subinfo in info["subdirs"].items():
                        if subinfo["exists"]:
                            response += f"  - `{subdir}/` ({subinfo['file_count']} files)\n"
                else:
                    response += f"- `{main_dir}/` (not created)\n"
            
            # Add recent scan history
            if workspace.scan_history:
                response += "\n📊 **Recent Scan History:**\n"
                recent_scans = workspace.scan_history[-5:]  # Last 5 scans
                for scan in recent_scans:
                    status_emoji = {"success": "✅", "failed": "❌", "partial": "⚠️"}.get(scan.get("status", "unknown"), "❓")
                    response += f"- {scan.get('scan_type', 'Unknown')} with {scan.get('tool_name', 'Unknown')} {status_emoji}\n"
                    response += f"  {scan.get('timestamp', '')[:16]} - {scan.get('results_summary', 'No summary')}\n"
            else:
                response += "\n📊 **Scan History:** No scans recorded yet\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to get workspace: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to get workspace {workspace_id}: {str(e)}"
            )]
    
    async def _handle_update_workspace_status(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle workspace status updates"""
        
        workspace_id = arguments["workspace_id"]
        status = arguments["status"]
        
        try:
            success = await self.workspace_manager.update_workspace_status(workspace_id, status)
            
            if success:
                response = f"✅ Updated workspace {workspace_id} status to: {status}"
            else:
                response = f"❌ Failed to update workspace {workspace_id} (workspace not found)"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to update workspace status: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to update workspace {workspace_id} status: {str(e)}"
            )]
    
    async def _handle_add_scan_record(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle adding scan records to workspace history"""
        
        workspace_id = arguments["workspace_id"]
        
        scan_info = {
            "scan_type": arguments["scan_type"],
            "tool_name": arguments["tool_name"],
            "status": arguments["status"],
            "results_summary": arguments.get("results_summary", ""),
            "findings_count": arguments.get("findings_count", 0)
        }
        
        try:
            success = await self.workspace_manager.add_scan_record(workspace_id, scan_info)
            
            if success:
                response = f"✅ Added {scan_info['scan_type']} scan record to workspace {workspace_id}"
                response += f"\n   Tool: {scan_info['tool_name']}"
                response += f"\n   Status: {scan_info['status']}"
                if scan_info["findings_count"]:
                    response += f"\n   Findings: {scan_info['findings_count']}"
            else:
                response = f"❌ Failed to add scan record to workspace {workspace_id} (workspace not found)"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to add scan record: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to add scan record to workspace {workspace_id}: {str(e)}"
            )]
    
    async def _handle_delete_workspace(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle workspace deletion"""
        
        workspace_id = arguments["workspace_id"]
        confirm = arguments.get("confirm", False)
        
        if not confirm:
            return [types.TextContent(
                type="text",
                text=f"❌ Workspace deletion requires confirmation. Set 'confirm' to true to delete workspace {workspace_id}."
            )]
        
        try:
            success = await self.workspace_manager.delete_workspace(workspace_id)
            
            if success:
                response = f"✅ Deleted workspace {workspace_id} and all its contents"
            else:
                response = f"❌ Failed to delete workspace {workspace_id} (workspace not found)"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to delete workspace: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to delete workspace {workspace_id}: {str(e)}"
            )]
    
    async def _handle_get_workspace_results(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle getting all results from a workspace"""
        
        workspace_id = arguments["workspace_id"]
        include_raw = arguments.get("include_raw", False)
        
        try:
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"❌ No results found for workspace {workspace_id}"
                )]
            
            response = f"📊 **Workspace Results: {workspace_id}**\n\n"
            response += f"**Target:** {all_results['target']}\n"
            response += f"**Scan Count:** {all_results['scan_count']}\n"
            response += f"**Last Scan:** {all_results['last_scan'][:16] if all_results['last_scan'] else 'None'}\n\n"
            
            # Summary statistics
            stats = all_results['summary_stats']
            response += f"📈 **Summary Statistics**\n"
            response += f"• Tools executed: {stats['tools_executed']}\n"
            response += f"• Subdomains found: {stats['total_subdomains_found']}\n"
            response += f"• Live hosts: {stats['total_live_hosts']}\n"
            response += f"• Vulnerabilities: {stats['total_vulnerabilities']}\n\n"
            
            # Tool results
            if all_results['tools']:
                response += f"🔧 **Tool Results**\n"
                for tool_name, tool_data in all_results['tools'].items():
                    response += f"**{tool_name.title()}**\n"
                    response += f"  Timestamp: {tool_data['timestamp'][:16]}\n"
                    response += f"  File: {tool_data['file_path']}\n"
                    
                    if include_raw and 'results' in tool_data:
                        # Show summary of results
                        results = tool_data['results']
                        if tool_name in ['subfinder', 'altdns']:
                            subdomains = results.get('subdomains', []) or results.get('generated_subdomains', [])
                            response += f"  Results: {len(subdomains)} items\n"
                        elif tool_name == 'httpx':
                            hosts = results.get('live_hosts', [])
                            response += f"  Results: {len(hosts)} live hosts\n"
                        elif tool_name == 'nuclei':
                            vulns = results.get('vulnerabilities', [])
                            response += f"  Results: {len(vulns)} vulnerabilities\n"
                    
                    response += "\n"
            else:
                response += "🔧 **Tool Results:** No tools executed yet\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to get workspace results: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to get results for workspace {workspace_id}: {str(e)}"
            )]
    
    async def _handle_get_tool_results(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle getting specific tool results from a workspace"""
        
        workspace_id = arguments["workspace_id"]
        tool_name = arguments["tool_name"]
        
        try:
            tool_results = await self.workspace_manager.get_tool_results(workspace_id, tool_name)
            
            if not tool_results:
                return [types.TextContent(
                    type="text",
                    text=f"❌ No results found for tool {tool_name} in workspace {workspace_id}"
                )]
            
            response = f"🔧 **{tool_name.title()} Results**\n\n"
            response += f"**Workspace:** {workspace_id}\n"
            response += f"**Total Executions:** {tool_results['total_executions']}\n\n"
            
            if tool_results['latest_execution']:
                latest = tool_results['latest_execution']
                response += f"📅 **Latest Execution**\n"
                response += f"**Timestamp:** {latest['timestamp'][:16]}\n"
                response += f"**Target:** {latest['target']}\n"
                response += f"**File:** {latest['file_path']}\n\n"
                
                # Show results summary
                results = latest['results']
                if tool_name in ['subfinder', 'altdns']:
                    subdomains = results.get('subdomains', []) or results.get('generated_subdomains', [])
                    response += f"**Results:** {len(subdomains)} subdomains found\n"
                    if subdomains:
                        response += "**Sample subdomains:**\n"
                        for subdomain in subdomains[:10]:
                            response += f"• {subdomain}\n"
                        if len(subdomains) > 10:
                            response += f"... and {len(subdomains) - 10} more\n"
                
                elif tool_name == 'httpx':
                    hosts = results.get('live_hosts', [])
                    response += f"**Results:** {len(hosts)} live hosts found\n"
                    if hosts:
                        response += "**Live hosts:**\n"
                        for host in hosts[:10]:
                            response += f"• {host.get('url', host.get('host', 'Unknown'))}\n"
                        if len(hosts) > 10:
                            response += f"... and {len(hosts) - 10} more\n"
                
                elif tool_name == 'nuclei':
                    vulns = results.get('vulnerabilities', [])
                    response += f"**Results:** {len(vulns)} vulnerabilities found\n"
                    if vulns:
                        response += "**Vulnerabilities:**\n"
                        for vuln in vulns[:5]:
                            severity = vuln.get('severity', 'unknown')
                            template = vuln.get('template_name', 'Unknown')
                            response += f"• {severity.upper()}: {template}\n"
                        if len(vulns) > 5:
                            response += f"... and {len(vulns) - 5} more\n"
            
            # Show execution history if multiple runs
            if tool_results['total_executions'] > 1:
                response += f"\n📊 **Execution History**\n"
                for i, execution in enumerate(tool_results['all_executions'][:5]):
                    response += f"{i+1}. {execution['timestamp'][:16]} - {execution['target']}\n"
                
                if tool_results['total_executions'] > 5:
                    response += f"... and {tool_results['total_executions'] - 5} more executions\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to get tool results: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to get {tool_name} results from workspace {workspace_id}: {str(e)}"
            )]
    
    async def _handle_get_latest_scan(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle getting latest scan results"""
        
        target = arguments["target"]
        
        try:
            # Search workspaces
            matching_workspaces = await self.workspace_manager.search_workspaces(target)
            
            if not matching_workspaces:
                return [types.TextContent(
                    type="text",
                    text=f"❌ No workspace found for target: {target}"
                )]
            
            # Sort by created date (newest first)
            matching_workspaces.sort(key=lambda w: w.metadata.created_date, reverse=True)
            latest_workspace = matching_workspaces[0]
            workspace_id = latest_workspace.metadata.workspace_id
            
            # Get results for latest workspace
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            
            if not all_results or not all_results.get("tools"):
                return [types.TextContent(
                    type="text",
                    text=f"📅 Workspace {workspace_id} found for {target}, but no scan results are available yet."
                )]
            
            # Use same formatting as get_workspace_results, but with summary only
            arguments["workspace_id"] = workspace_id
            arguments["include_raw"] = False
            return await self._handle_get_workspace_results(arguments)
            
        except Exception as e:
            logger.error(f"Failed to get latest scan: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to get latest scan for {target}: {str(e)}"
            )]
    
    async def _handle_generate_report(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle report generation"""
        
        workspace_id = arguments["workspace_id"]
        report_type_str = arguments.get("report_type", "technical_report")
        format_str = arguments.get("format", "markdown")
        save_to_workspace = arguments.get("save_to_workspace", True)
        options = arguments.get("options", {})
        
        try:
            # Convert string enums to enum objects
            report_type = ReportType(report_type_str)
            report_format = ReportFormat("md" if format_str == "markdown" else format_str)
            
            logger.info(f"Generating {report_type.value} report for workspace {workspace_id}")
            
            # Generate the report
            result = await self.report_generator.generate_report(
                workspace_id, report_type, report_format, options
            )
            
            if not result["success"]:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Failed to generate report: {result.get('error', 'Unknown error')}"
                )]
            
            content = result["content"]
            metadata = result["metadata"]
            
            # Save report if requested
            report_path = ""
            if save_to_workspace:
                try:
                    report_path = await self.report_generator.save_report(workspace_id, content, metadata)
                    logger.info(f"Report saved to {report_path}")
                except Exception as e:
                    logger.warning(f"Failed to save report: {e}")
            
            # Format response
            response = f"📄 **Report Generated Successfully**\n\n"
            response += f"**Type:** {metadata['report_type'].replace('_', ' ').title()}\n"
            response += f"**Format:** {metadata['format'].upper()}\n"
            response += f"**Target:** {metadata['target']}\n"
            response += f"**Findings:** {metadata['total_findings']} total "
            
            if metadata['critical_findings'] > 0:
                response += f"({metadata['critical_findings']} critical, {metadata['high_findings']} high)\n"
            else:
                response += f"({metadata['high_findings']} high priority)\n"
            
            if report_path:
                response += f"**Saved to:** {report_path}\n"
            
            response += f"\n📋 **Report Preview:**\n\n"
            
            # Show first 1000 characters of report
            preview = content[:1000]
            if len(content) > 1000:
                preview += "\n\n... (truncated - full report saved to workspace)"
            
            response += preview
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to generate report: {str(e)}"
            )]
    
    async def _handle_export_findings(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle exporting findings"""
        
        workspace_id = arguments["workspace_id"]
        severity_filter = arguments.get("severity_filter", ["critical", "high"])
        export_format = arguments.get("format", "json")
        include_evidence = arguments.get("include_evidence", True)
        
        try:
            logger.info(f"Exporting findings from workspace {workspace_id}")
            
            # Get workspace data
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"❌ No results found for workspace {workspace_id}"
                )]
            
            # Extract findings using report generator
            from ..core.report_generator import SeverityLevel
            report_data = await self.report_generator._prepare_report_data(workspace_id, {})
            
            if not report_data:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Failed to prepare data for export"
                )]
            
            # Filter findings by severity
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            
            allowed_severities = [severity_map[s] for s in severity_filter if s in severity_map]
            filtered_findings = [f for f in report_data.findings if f.severity in allowed_severities]
            
            if not filtered_findings:
                return [types.TextContent(
                    type="text",
                    text=f"✅ No findings match the specified severity filter: {', '.join(severity_filter)}"
                )]
            
            # Format export data
            if export_format == "json":
                export_data = []
                for finding in filtered_findings:
                    finding_data = {
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "description": finding.description,
                        "impact": finding.impact,
                        "affected_url": finding.affected_url,
                        "recommendation": finding.recommendation,
                        "cve_references": finding.cve_references,
                        "discovery_method": finding.discovery_method
                    }
                    
                    if include_evidence:
                        finding_data["evidence"] = finding.evidence
                        finding_data["proof_of_concept"] = finding.proof_of_concept
                    
                    export_data.append(finding_data)
                
                export_content = json.dumps(export_data, indent=2)
                
            elif export_format == "csv":
                # Basic CSV format
                lines = ["title,severity,affected_url,description"]
                for finding in filtered_findings:
                    # Escape commas and quotes for CSV
                    title = finding.title.replace(',', ';').replace('"', '""')
                    desc = finding.description.replace(',', ';').replace('"', '""')[:100]
                    lines.append(f'"{title}",{finding.severity.value},"{finding.affected_url}","{desc}"')
                
                export_content = "\n".join(lines)
                
            else:  # markdown
                export_content = f"# Security Findings Export - {all_results['target']}\n\n"
                export_content += f"**Export Date:** {datetime.now().strftime('%Y-%m-%d')}\n"
                export_content += f"**Severity Filter:** {', '.join(severity_filter)}\n"
                export_content += f"**Total Findings:** {len(filtered_findings)}\n\n"
                
                for i, finding in enumerate(filtered_findings, 1):
                    export_content += f"## {i}. {finding.title}\n\n"
                    export_content += f"**Severity:** {finding.severity.value.upper()}\n"
                    export_content += f"**Affected URL:** {finding.affected_url}\n\n"
                    export_content += f"**Description:** {finding.description}\n\n"
                    export_content += f"**Impact:** {finding.impact}\n\n"
                    export_content += f"**Recommendation:** {finding.recommendation}\n\n"
                    export_content += "---\n\n"
            
            # Save export to workspace
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if workspace:
                exports_dir = workspace.workspace_path / "exports"
                exports_dir.mkdir(exist_ok=True)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"findings_export_{timestamp}.{export_format}"
                export_path = exports_dir / filename
                
                with open(export_path, 'w') as f:
                    f.write(export_content)
                
                response = f"📤 **Findings Export Complete**\n\n"
                response += f"**Workspace:** {workspace_id}\n"
                response += f"**Format:** {export_format.upper()}\n"
                response += f"**Severity Filter:** {', '.join(severity_filter)}\n"
                response += f"**Exported Findings:** {len(filtered_findings)}\n"
                response += f"**Saved to:** {export_path}\n\n"
                
                # Show summary of exported findings
                severity_counts = {}
                for finding in filtered_findings:
                    sev = finding.severity.value
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                response += "**Severity Breakdown:**\n"
                for severity, count in severity_counts.items():
                    response += f"• {severity.title()}: {count}\n"
                
                return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to export findings: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to export findings: {str(e)}"
            )]
    
    async def _handle_create_submission(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle creating bug bounty submission"""
        
        workspace_id = arguments["workspace_id"]
        platform = arguments.get("platform", "hackerone")
        finding_ids = arguments.get("finding_ids", [])
        include_poc = arguments.get("include_proof_of_concept", True)
        
        try:
            logger.info(f"Creating bug bounty submission for workspace {workspace_id}")
            
            # Prepare options for bug bounty report
            options = {
                "platform": platform,
                "include_proof_of_concept": include_poc
            }
            
            # Generate bug bounty report
            result = await self.report_generator.generate_report(
                workspace_id, 
                ReportType.BUG_BOUNTY_SUBMISSION, 
                ReportFormat.MARKDOWN, 
                options
            )
            
            if not result["success"]:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Failed to create submission: {result.get('error', 'Unknown error')}"
                )]
            
            content = result["content"]
            metadata = result["metadata"]
            
            # Save submission to workspace
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if workspace:
                submissions_dir = workspace.workspace_path / "submissions"
                submissions_dir.mkdir(exist_ok=True)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"bug_bounty_submission_{platform}_{timestamp}.md"
                submission_path = submissions_dir / filename
                
                with open(submission_path, 'w') as f:
                    f.write(content)
                
                response = f"🎯 **Bug Bounty Submission Created**\n\n"
                response += f"**Platform:** {platform.title()}\n"
                response += f"**Target:** {metadata['target']}\n"
                response += f"**Findings:** {metadata['total_findings']} total"
                
                if metadata['critical_findings'] > 0:
                    response += f" ({metadata['critical_findings']} critical, {metadata['high_findings']} high)\n"
                else:
                    response += f" ({metadata['high_findings']} high severity)\n"
                
                response += f"**Saved to:** {submission_path}\n\n"
                
                # Show preview
                response += "📋 **Submission Preview:**\n\n"
                preview = content[:800]
                if len(content) > 800:
                    preview += "\n\n... (truncated - full submission saved to workspace)"
                
                response += preview
                
                # Add submission tips
                response += f"\n\n💡 **Submission Tips:**\n"
                response += f"• Review all findings for accuracy before submitting\n"
                response += f"• Ensure you have authorization to test the target\n"
                response += f"• Follow {platform} submission guidelines\n"
                response += f"• Include clear reproduction steps\n"
                
                return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to create submission: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to create bug bounty submission: {str(e)}"
            )]
    
    async def _handle_collect_evidence(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle evidence collection for workspace findings"""
        
        try:
            workspace_id = arguments["workspace_id"]
            finding_ids = arguments.get("finding_ids", [])
            evidence_types = arguments.get("evidence_types", ["screenshot", "http_request", "http_response", "payload", "proof_of_concept"])
            
            if not self.evidence_collector:
                return [types.TextContent(
                    type="text",
                    text="❌ Evidence collector not available"
                )]
            
            # Get workspace to validate
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text", 
                    text=f"❌ Workspace {workspace_id} not found"
                )]
            
            response = f"🔍 **Evidence Collection for {workspace.metadata.target}**\n\n"
            
            # Get all results from workspace to find vulnerabilities/findings
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"❌ No scan results found in workspace {workspace_id}"
                )]
            
            evidence_collected = 0
            findings_processed = 0
            
            # Process nuclei vulnerabilities if available
            if 'nuclei' in all_results.get('tools', {}):
                nuclei_data = all_results['tools']['nuclei']
                vulnerabilities = nuclei_data.get('results', {}).get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    # Skip if specific finding IDs requested and this isn't one
                    vuln_id = vuln.get('template_id', 'unknown')
                    if finding_ids and vuln_id not in finding_ids:
                        continue
                    
                    findings_processed += 1
                    target_url = vuln.get('matched_at') or vuln.get('host', '')
                    
                    if target_url:
                        evidence_items = await self.evidence_collector.collect_evidence_for_finding(
                            workspace_id=workspace_id,
                            finding_data=vuln,
                            target_url=target_url,
                            vulnerability_type=vuln_id
                        )
                        evidence_collected += len(evidence_items)
            
            # Process live hosts if available
            if 'httpx' in all_results.get('tools', {}):
                httpx_data = all_results['tools']['httpx']
                live_hosts = httpx_data.get('results', {}).get('live_hosts', [])
                
                # Only collect if no specific finding IDs or if requesting host evidence
                if not finding_ids or 'live_hosts' in finding_ids:
                    evidence_results = await self.evidence_collector.collect_live_host_evidence(
                        workspace_id=workspace_id,
                        live_hosts=live_hosts
                    )
                    
                    for url, evidence_items in evidence_results.items():
                        evidence_collected += len(evidence_items)
                        findings_processed += 1
            
            if evidence_collected > 0:
                response += f"✅ **Collection Complete**\n"
                response += f"• **Findings Processed:** {findings_processed}\n"
                response += f"• **Evidence Items Collected:** {evidence_collected}\n"
                response += f"• **Evidence Types:** {', '.join(evidence_types)}\n\n"
                response += f"📁 Evidence saved to: `{workspace.workspace_path}/reports/evidence/`\n\n"
                response += f"💡 Use `list_evidence` to view collected evidence"
            else:
                response += f"⚠️ **No Evidence Collected**\n"
                response += f"• **Findings Processed:** {findings_processed}\n"
                response += f"• No evidence could be collected for the specified criteria\n"
                response += f"• Check that workspace contains vulnerability or live host data"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to collect evidence: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to collect evidence: {str(e)}"
            )]
    
    async def _handle_list_evidence(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle listing evidence for workspace"""
        
        try:
            workspace_id = arguments["workspace_id"]
            finding_id = arguments.get("finding_id")
            evidence_type = arguments.get("evidence_type", "all")
            
            if not self.evidence_collector:
                return [types.TextContent(
                    type="text",
                    text="❌ Evidence collector not available"
                )]
            
            # Get workspace to validate
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text", 
                    text=f"❌ Workspace {workspace_id} not found"
                )]
            
            if finding_id:
                # Get evidence for specific finding
                evidence_items = await self.evidence_collector.get_evidence_for_finding(workspace_id, finding_id)
                
                if not evidence_items:
                    return [types.TextContent(
                        type="text",
                        text=f"📁 No evidence found for finding {finding_id}"
                    )]
                
                response = f"📋 **Evidence for Finding: {finding_id}**\n\n"
                
                for evidence in evidence_items:
                    if evidence_type == "all" or evidence.evidence_type.value == evidence_type:
                        response += f"**{evidence.title}**\n"
                        response += f"• **Type:** {evidence.evidence_type.value}\n"
                        response += f"• **Target:** {evidence.target_url}\n"
                        response += f"• **Size:** {evidence.size_bytes} bytes\n"
                        response += f"• **Created:** {evidence.timestamp}\n"
                        if evidence.file_path:
                            response += f"• **File:** {evidence.file_path}\n"
                        response += f"• **Description:** {evidence.description}\n\n"
                
            else:
                # Get all evidence for workspace
                evidence_summary = await self.evidence_collector.list_evidence_for_workspace(workspace_id)
                
                response = f"📁 **Evidence Summary for {workspace.metadata.target}**\n\n"
                response += f"• **Total Evidence:** {evidence_summary.get('evidence_count', 0)} items\n"
                response += f"• **Findings with Evidence:** {evidence_summary.get('finding_count', 0)}\n"
                
                if evidence_summary.get('findings'):
                    response += f"\n**📋 Evidence by Finding:**\n\n"
                    
                    for finding in evidence_summary['findings']:
                        finding_id = finding.get('finding_id', 'unknown')
                        evidence_count = finding.get('evidence_count', 0)
                        response += f"**{finding_id}** - {evidence_count} items\n"
                        
                        for item in finding.get('evidence_items', []):
                            if evidence_type == "all" or item.get('evidence_type') == evidence_type:
                                response += f"  • {item.get('title')} ({item.get('evidence_type')})\n"
                        response += "\n"
                
                if evidence_summary.get('evidence_directory'):
                    response += f"📂 **Evidence Directory:** {evidence_summary['evidence_directory']}\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to list evidence: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to list evidence: {str(e)}"
            )]
    
    async def _handle_attach_evidence(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle attaching evidence to findings"""
        
        try:
            workspace_id = arguments["workspace_id"]
            finding_id = arguments["finding_id"]
            evidence_data = arguments["evidence_data"]
            
            if not self.evidence_collector:
                return [types.TextContent(
                    type="text",
                    text="❌ Evidence collector not available"
                )]
            
            # Get workspace to validate
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text", 
                    text=f"❌ Workspace {workspace_id} not found"
                )]
            
            # Create evidence object from provided data
            from ..core.evidence_collector import Evidence, EvidenceType
            
            evidence = Evidence(
                evidence_id=f"{finding_id}_manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                evidence_type=EvidenceType(evidence_data["evidence_type"]),
                finding_id=finding_id,
                target_url=workspace.metadata.target,  # Default to workspace target
                title=evidence_data["title"],
                description=evidence_data["description"],
                content=evidence_data.get("content"),
                file_path=evidence_data.get("file_path")
            )
            
            # Save evidence to file if content provided
            if evidence.content and not evidence.file_path:
                saved = await self.evidence_collector._save_evidence_to_file(workspace_id, evidence)
                if not saved:
                    return [types.TextContent(
                        type="text",
                        text="❌ Failed to save evidence content to file"
                    )]
            
            # Save evidence index
            await self.evidence_collector._save_evidence_index(workspace_id, finding_id, [evidence])
            
            response = f"📎 **Evidence Attached Successfully**\n\n"
            response += f"• **Finding ID:** {finding_id}\n"
            response += f"• **Evidence Type:** {evidence.evidence_type.value}\n"
            response += f"• **Title:** {evidence.title}\n"
            response += f"• **Evidence ID:** {evidence.evidence_id}\n"
            
            if evidence.file_path:
                response += f"• **File Path:** {evidence.file_path}\n"
            
            response += f"\n💡 Use `list_evidence` to view all evidence for this finding"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to attach evidence: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to attach evidence: {str(e)}"
            )]
    
    async def _handle_view_dashboard(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle viewing comprehensive workspace dashboard"""
        
        try:
            workspace_id = arguments["workspace_id"]
            include_ai = arguments.get("include_ai", True)
            show_visuals = arguments.get("show_visuals", True)
            
            if not self.dashboard:
                return [types.TextContent(
                    type="text",
                    text="❌ Dashboard functionality not available"
                )]
            
            # Get workspace to validate
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text", 
                    text=f"❌ Workspace {workspace_id} not found"
                )]
            
            # Generate dashboard
            dashboard_data = await self.dashboard.generate_dashboard(workspace_id, include_ai)
            
            if dashboard_data.get("status") == "failed":
                return [types.TextContent(
                    type="text",
                    text=f"❌ Failed to generate dashboard: {dashboard_data.get('error')}"
                )]
            
            # Build dashboard response
            summary = dashboard_data["summary"]
            visuals = dashboard_data.get("visuals", {})
            
            response = f"📊 **BugHound Workspace Dashboard**\n\n"
            response += f"**Target:** {summary.target}\n"
            response += f"**Workspace:** {workspace_id}\n"
            response += f"**Status:** {summary.scan_status}\n"
            response += f"**Last Updated:** {summary.last_updated[:19].replace('T', ' ')}\n\n"
            
            # Risk Assessment Overview
            risk = summary.risk_assessment
            response += f"🎯 **Risk Assessment**\n"
            response += f"• **Overall Risk Level:** {risk.overall_risk_level.value.upper()}\n"
            response += f"• **Risk Score:** {risk.risk_score}/10\n"
            response += f"• **Business Impact:** {risk.business_impact}\n"
            response += f"• **Urgency:** {risk.urgency_level}\n\n"
            
            # Key Statistics
            assets = summary.asset_stats
            vulns = summary.vulnerability_breakdown
            response += f"📈 **Key Statistics**\n"
            response += f"• **Subdomains Discovered:** {assets.subdomains_discovered}\n"
            response += f"• **Live Hosts:** {assets.live_hosts}\n"
            response += f"• **Open Ports:** {assets.open_ports}\n"
            response += f"• **Total Vulnerabilities:** {vulns.total_vulnerabilities}\n"
            response += f"• **Critical/High Severity:** {vulns.critical_count}/{vulns.high_count}\n"
            response += f"• **Technologies Identified:** {assets.technologies_identified}\n\n"
            
            # Visual Charts (if enabled)
            if show_visuals and visuals:
                response += f"📊 **Risk Score Visualization**\n```\n{visuals.get('risk_gauge', '')}\n```\n\n"
                
                if vulns.total_vulnerabilities > 0:
                    response += f"🎯 **Vulnerability Distribution**\n```\n{visuals.get('vulnerability_chart', '')}\n```\n\n"
                
                response += f"📋 **Asset Discovery**\n```\n{visuals.get('asset_progress', '')}\n```\n\n"
                
                response += f"⚙️ **Scan Performance**\n```\n{visuals.get('efficiency_meter', '')}\n```\n\n"
            
            # AI Insights (if available)
            if include_ai and summary.ai_insights:
                response += f"🤖 **AI-Generated Insights**\n"
                for insight in summary.ai_insights[:3]:  # Show top 3
                    response += f"• {insight}\n"
                response += "\n"
            
            # Top Recommendations
            if summary.top_recommendations:
                response += f"🎯 **Top Recommendations**\n"
                for i, rec in enumerate(summary.top_recommendations[:5], 1):
                    response += f"{i}. {rec}\n"
                response += "\n"
            
            # Change Metrics (if available)
            changes = summary.change_metrics
            if changes.has_baseline:
                response += f"🔄 **Change Analysis**\n"
                response += f"• **Risk Delta:** {changes.risk_delta.replace('_', ' ').title()}\n"
                response += f"• **New Assets:** {changes.new_assets_discovered}\n"
                response += f"• **New Vulnerabilities:** {changes.new_vulnerabilities}\n"
                response += f"• **Fixed Issues:** {changes.fixed_vulnerabilities}\n"
                response += f"• **Change Rate:** {changes.change_percentage:.1f}%\n\n"
            
            # Evidence Summary
            evidence = summary.evidence_summary
            if evidence.get("total_evidence", 0) > 0:
                response += f"📎 **Evidence Collection**\n"
                response += f"• **Total Evidence:** {evidence['total_evidence']} items\n"
                response += f"• **Findings with Evidence:** {evidence['findings_with_evidence']}\n\n"
            
            # Technology Stack Summary
            tech = summary.technology_stack
            if any([tech.web_servers, tech.programming_languages, tech.frameworks]):
                response += f"🛠️ **Technology Stack**\n"
                if tech.web_servers:
                    response += f"• **Web Servers:** {', '.join(tech.web_servers[:3])}\n"
                if tech.programming_languages:
                    response += f"• **Languages:** {', '.join(tech.programming_languages[:3])}\n"
                if tech.frameworks:
                    response += f"• **Frameworks:** {', '.join(tech.frameworks[:3])}\n"
                if tech.cms_platforms:
                    response += f"• **CMS/Platforms:** {', '.join(tech.cms_platforms[:3])}\n"
                response += "\n"
            
            # Scan Metrics
            metrics = summary.scan_metrics
            response += f"⏱️ **Scan Performance**\n"
            response += f"• **Duration:** {metrics.scan_duration_minutes} minutes\n"
            response += f"• **Tools Executed:** {metrics.tools_executed}\n"
            response += f"• **Success Rate:** {metrics.success_rate:.1f}%\n"
            response += f"• **Data Points Collected:** {metrics.data_points_collected}\n"
            response += f"• **Efficiency Score:** {metrics.efficiency_score:.1f} items/min\n\n"
            
            # Footer
            response += f"💡 **Next Steps:**\n"
            if vulns.critical_count > 0:
                response += f"• Address {vulns.critical_count} critical vulnerabilities immediately\n"
            if vulns.high_count > 0:
                response += f"• Review {vulns.high_count} high-severity findings\n"
            response += f"• Use `generate_summary` for executive overview\n"
            response += f"• Use `generate_report` for detailed technical reports\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to view dashboard: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to view dashboard: {str(e)}"
            )]
    
    async def _handle_get_statistics(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle getting detailed workspace statistics"""
        
        try:
            workspace_id = arguments["workspace_id"]
            include_breakdown = arguments.get("include_breakdown", True)
            compare_with_baseline = arguments.get("compare_with_baseline", False)
            
            if not self.dashboard:
                return [types.TextContent(
                    type="text",
                    text="❌ Dashboard functionality not available"
                )]
            
            # Get workspace to validate
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text", 
                    text=f"❌ Workspace {workspace_id} not found"
                )]
            
            # Generate summary (use cached if available)
            summary = await self.dashboard.load_workspace_summary(workspace_id)
            if not summary:
                # Generate fresh summary
                dashboard_data = await self.dashboard.generate_dashboard(workspace_id, False)
                summary = dashboard_data.get("summary")
            
            if not summary:
                return [types.TextContent(
                    type="text",
                    text="❌ Failed to load workspace statistics"
                )]
            
            response = f"📊 **Detailed Statistics for {summary.target}**\n\n"
            
            # Asset Discovery Statistics
            assets = summary.asset_stats
            response += f"🔍 **Asset Discovery Metrics**\n"
            response += f"• Subdomains Discovered: {assets.subdomains_discovered}\n"
            response += f"• Live Hosts: {assets.live_hosts}\n"
            response += f"• Total Ports Scanned: {assets.total_ports_scanned}\n"
            response += f"• Open Ports: {assets.open_ports}\n"
            response += f"• Unique Services: {assets.unique_services}\n"
            response += f"• Technologies Identified: {assets.technologies_identified}\n"
            response += f"• URLs Discovered: {assets.urls_discovered}\n"
            response += f"• Endpoints Found: {assets.endpoints_found}\n\n"
            
            # Vulnerability Statistics
            vulns = summary.vulnerability_breakdown
            response += f"🛡️ **Vulnerability Analysis**\n"
            response += f"• Total Vulnerabilities: {vulns.total_vulnerabilities}\n"
            response += f"• Critical Severity: {vulns.critical_count}\n"
            response += f"• High Severity: {vulns.high_count}\n"
            response += f"• Medium Severity: {vulns.medium_count}\n"
            response += f"• Low Severity: {vulns.low_count}\n"
            response += f"• Info Level: {vulns.info_count}\n"
            response += f"• Unique Vulnerability Types: {vulns.unique_vulnerability_types}\n"
            response += f"• Exploitable Vulnerabilities: {vulns.exploitable_count}\n\n"
            
            # Risk Assessment Details
            risk = summary.risk_assessment
            response += f"⚠️ **Risk Assessment Details**\n"
            response += f"• Overall Risk Level: {risk.overall_risk_level.value.upper()}\n"
            response += f"• Risk Score: {risk.risk_score}/10\n"
            response += f"• Attack Surface Score: {risk.attack_surface_score}/10\n"
            response += f"• Vulnerability Density: {risk.vulnerability_density:.2f}\n"
            response += f"• Exploitability Rating: {risk.exploitability_rating}\n"
            response += f"• Business Impact: {risk.business_impact}\n"
            response += f"• Urgency Level: {risk.urgency_level}\n\n"
            
            # Scan Performance Metrics
            metrics = summary.scan_metrics
            response += f"⏱️ **Scan Performance Metrics**\n"
            response += f"• Scan Duration: {metrics.scan_duration_minutes} minutes\n"
            response += f"• Tools Executed: {metrics.tools_executed}\n"
            response += f"• Success Rate: {metrics.success_rate:.1f}%\n"
            response += f"• Data Points Collected: {metrics.data_points_collected}\n"
            response += f"• Efficiency Score: {metrics.efficiency_score:.2f} items/min\n"
            response += f"• Scan Start Time: {metrics.scan_start_time}\n"
            response += f"• Last Updated: {metrics.last_updated}\n\n"
            
            # Technology Stack Breakdown (if requested)
            if include_breakdown:
                tech = summary.technology_stack
                response += f"🛠️ **Technology Stack Breakdown**\n"
                response += f"• Web Servers ({len(tech.web_servers)}): {', '.join(tech.web_servers) if tech.web_servers else 'None detected'}\n"
                response += f"• Programming Languages ({len(tech.programming_languages)}): {', '.join(tech.programming_languages) if tech.programming_languages else 'None detected'}\n"
                response += f"• Frameworks ({len(tech.frameworks)}): {', '.join(tech.frameworks) if tech.frameworks else 'None detected'}\n"
                response += f"• CMS/Platforms ({len(tech.cms_platforms)}): {', '.join(tech.cms_platforms) if tech.cms_platforms else 'None detected'}\n"
                response += f"• JavaScript Libraries ({len(tech.javascript_libraries)}): {', '.join(tech.javascript_libraries) if tech.javascript_libraries else 'None detected'}\n"
                response += f"• Cloud Services ({len(tech.cloud_services)}): {', '.join(tech.cloud_services) if tech.cloud_services else 'None detected'}\n\n"
            
            # Change Comparison (if requested and available)
            if compare_with_baseline:
                changes = summary.change_metrics
                if changes.has_baseline:
                    response += f"🔄 **Change Comparison with Baseline**\n"
                    response += f"• Baseline Scan Date: {changes.last_scan_date}\n"
                    response += f"• Risk Delta: {changes.risk_delta.replace('_', ' ').title()}\n"
                    response += f"• New Assets Discovered: {changes.new_assets_discovered}\n"
                    response += f"• Assets Removed: {changes.removed_assets}\n"
                    response += f"• New Vulnerabilities: {changes.new_vulnerabilities}\n"
                    response += f"• Fixed Vulnerabilities: {changes.fixed_vulnerabilities}\n"
                    response += f"• Overall Change Rate: {changes.change_percentage:.1f}%\n\n"
                else:
                    response += f"🔄 **Change Comparison**: No baseline scan available\n\n"
            
            # Evidence Summary
            evidence = summary.evidence_summary
            response += f"📎 **Evidence Collection Summary**\n"
            response += f"• Total Evidence Items: {evidence.get('total_evidence', 0)}\n"
            response += f"• Findings with Evidence: {evidence.get('findings_with_evidence', 0)}\n\n"
            
            # Quick Actions
            response += f"🎯 **Quick Actions Available**\n"
            response += f"• `view_dashboard` - Visual overview with charts\n"
            response += f"• `generate_summary` - Executive summary\n"
            response += f"• `generate_report` - Technical reports\n"
            response += f"• `list_evidence` - View collected evidence\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to get statistics: {str(e)}"
            )]
    async def run(self):
        """Run the MCP server"""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="bughound-workspace",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


async def main():
    """Main entry point"""
    try:
        server = BugHoundWorkspaceServer()
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == "__main__":
    """Allow running the server standalone for testing"""
    import sys
    sys.stderr.write("BugHound Workspace MCP Server — stdio mode\n")
    sys.stderr.flush()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nServer stopped\n")
    except Exception as e:
        sys.stderr.write(f"\nError: {e}\n")
        exit(1)