#!/usr/bin/env python3
"""
BugHound Decision Engine MCP Server

Provides intelligence and planning capabilities for the BugHound framework.
Uses the DecisionEngine to analyze reconnaissance data and generate
actionable ScanPlans.
"""

import sys
import json
import logging
from typing import Any, Dict, List

import mcp.types as types
from mcp.server import Server

from ..core.workspace_manager import WorkspaceManager
from ..core.decision_engine import DecisionEngine

# Configure logging — stderr only
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

class BugHoundDecisionServer:
    """MCP Server for the Decision Engine operations"""

    def __init__(self):
        self.server = Server("bughound-decision")
        self.workspace_manager = WorkspaceManager()
        self.decision_engine = DecisionEngine(self.workspace_manager)
        
        self.setup_handlers()

    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """List available decision operations"""
            return [
                types.Tool(
                    name="generate_scan_plan",
                    description="Generates a computationally sound ScanPlan based on deep recon data.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_id": {
                                "type": "string",
                                "description": "The target workspace ID to analyze."
                            },
                            "mode": {
                                "type": "string",
                                "enum": ["STEALTH", "NORMAL", "INTENSE"],
                                "description": "The operational mode for the scan."
                            },
                            "budget_minutes": {
                                "type": "integer",
                                "description": "Maximum time budget in minutes for the scan plan.",
                                "default": 60
                            }
                        },
                        "required": ["workspace_id", "mode"]
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: Dict[str, Any]
        ) -> List[types.TextContent]:
            """Handle tool execution requests"""
            logger.info(f"Executing decision tool: {name}")
            
            try:
                if name == "generate_scan_plan":
                    return await self._handle_generate_scan_plan(arguments)
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

    async def _handle_generate_scan_plan(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle generate scan plan request"""
        workspace_id = arguments["workspace_id"]
        mode = arguments.get("mode", "NORMAL")
        budget_minutes = arguments.get("budget_minutes", 60)
        
        try:
            # First, check if the workspace exists
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Workspace {workspace_id} not found."
                )]

            # In a real scenario, we might want to aggregate data from deep recon
            # For now, we will use the Decision Engine directly which handles pulling what it needs
            # We'll pass a basic context mapping derived from the results
            
            all_results = await self.workspace_manager.get_all_results(workspace_id)
            
            # Use DecisionEngine to decide the plan
            scan_plan = self.decision_engine.decide_plan(
                workspace_id=workspace_id,
                mode=mode,
                budget_minutes=budget_minutes,
                context_summary=all_results
            )
            
            # Format output beautifully so the AI and user can read it clearly
            plan_dict = scan_plan.to_dict()
            json_output = json.dumps(plan_dict, indent=2)
            
            response = f"✅ **ScanPlan Generated Successfully for {workspace.metadata.target}**\n\n"
            response += f"```json\n{json_output}\n```"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to generate scan plan: {e}")
            return [types.TextContent(
                type="text",
                text=f"❌ Failed to generate scan plan: {str(e)}"
            )]

async def main():
    """Run the decision MCP server"""
    server = BugHoundDecisionServer()
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            mcp.server.models.InitializationOptions(
                server_name="bughound-decision",
                server_version="0.1.0",
                capabilities=mcp.server.models.ServerCapabilities(),
            )
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
