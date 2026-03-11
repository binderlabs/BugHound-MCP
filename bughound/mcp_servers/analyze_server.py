"""
BugHound Pattern Analysis MCP Server

Provides pattern-based analysis capabilities for reconnaissance data.
Analyzes subdomains, technologies, and live hosts to generate actionable security insights.
No external AI API calls - designed for MCP architecture where Claude Desktop handles AI interpretation.
"""

import asyncio
import json
import logging
import os
from typing import Any, Dict, List
from pathlib import Path

import mcp.types as types
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio

# Add the bughound package to the path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ..core.pattern_analyzer import PatternAnalyzer, create_pattern_analyzer, ComprehensiveAnalysis
from ..core.subdomain_discovery import SubdomainDiscovery
from ..core.subdomain_enrichment import SubdomainEnrichment
from ..tools.recon.httpx import HTTPxTool

logger = logging.getLogger(__name__)


class BugHoundAnalyzeServer:
    """
    BugHound Pattern Analysis MCP Server

    Provides intelligent pattern-based analysis of reconnaissance data.
    Focuses on security insights and actionable recommendations.
    No external AI API calls - designed for pure MCP architecture.
    """

    def __init__(self):
        """Initialize the analysis server"""
        self.server = Server("bughound-analyze")

        # Initialize pattern analyzer (no external AI needed)
        self.pattern_analyzer = create_pattern_analyzer()
        logger.info("Pattern analyzer initialized (pure MCP - no external AI)")

        # Initialize other engines for data processing
        self.discovery_engine = SubdomainDiscovery()
        self.enrichment_engine = SubdomainEnrichment()
        self.httpx_tool = HTTPxTool()

        self.setup_handlers()

        logger.info("BugHound Pattern Analysis Server initialized")
    
    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available analysis tools"""
            return [
                types.Tool(
                    name="analyze_recon_results",
                    description="Analyze reconnaissance results using pattern-based intelligence to provide security insights and recommendations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain that was analyzed"
                            },
                            "subdomains": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of discovered subdomains"
                            },
                            "live_hosts": {
                                "type": "array",
                                "items": {"type": "object"},
                                "description": "Live host data from httpx analysis"
                            },
                            "technologies": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Detected technologies"
                            },
                            "analysis_depth": {
                                "type": "string",
                                "enum": ["quick", "standard", "deep"],
                                "description": "Depth of analysis to perform",
                                "default": "standard"
                            }
                        },
                        "required": ["target", "subdomains"]
                    }
                ),
                types.Tool(
                    name="analyze_patterns",
                    description="Analyze subdomain patterns to identify security-relevant naming conventions and predict additional targets",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain"
                            },
                            "subdomains": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of discovered subdomains"
                            }
                        },
                        "required": ["target", "subdomains"]
                    }
                ),
                types.Tool(
                    name="analyze_technologies",
                    description="Analyze detected technologies for vulnerabilities and testing recommendations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "technologies": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of detected technologies"
                            },
                            "live_hosts": {
                                "type": "array",
                                "items": {"type": "object"},
                                "description": "Live host data with technology information"
                            }
                        },
                        "required": ["technologies"]
                    }
                ),
                types.Tool(
                    name="generate_testing_plan",
                    description="Generate a comprehensive security testing plan based on analysis results",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "analysis_results": {
                                "type": "object",
                                "description": "Results from previous analysis"
                            },
                            "priority_focus": {
                                "type": "string",
                                "enum": ["speed", "coverage", "depth"],
                                "description": "Testing approach priority",
                                "default": "coverage"
                            },
                            "time_budget": {
                                "type": "string",
                                "description": "Available time for testing (e.g., '4 hours', '2 days')",
                                "default": "4 hours"
                            }
                        },
                        "required": ["analysis_results"]
                    }
                ),
                types.Tool(
                    name="check_ai_status",
                    description="Check the status of pattern analysis capabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str, 
            arguments: dict[str, Any]
        ) -> list[types.TextContent]:
            """Handle tool execution requests"""
            
            logger.info(f"Pattern Analysis tool called: {name}")
            
            if name == "analyze_recon_results":
                return await self._handle_analyze_recon_results(arguments)
            elif name == "analyze_patterns":
                return await self._handle_analyze_patterns(arguments)
            elif name == "analyze_technologies":
                return await self._handle_analyze_technologies(arguments)
            elif name == "generate_testing_plan":
                return await self._handle_generate_testing_plan(arguments)
            elif name == "check_ai_status":
                return await self._handle_check_ai_status(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    async def _handle_analyze_recon_results(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle comprehensive reconnaissance analysis"""
        
        try:
            # Extract arguments
            target = arguments.get("target")
            subdomains = arguments.get("subdomains", [])
            live_hosts = arguments.get("live_hosts", [])
            technologies = arguments.get("technologies", [])
            analysis_depth = arguments.get("analysis_depth", "standard")

            if not target:
                raise ValueError("Target domain is required")

            if not subdomains:
                raise ValueError("Subdomains list is required")

            logger.info(f"Analyzing recon results for {target}")
            logger.info(f"Data: {len(subdomains)} subdomains, {len(live_hosts)} live hosts, {len(technologies)} technologies")

            # Perform comprehensive pattern-based analysis
            analysis = await self.pattern_analyzer.analyze_recon_results(
                target=target,
                subdomains=subdomains,
                live_hosts=live_hosts,
                technologies=technologies
            )
            
            # Format response
            response_text = self._format_comprehensive_analysis(analysis, analysis_depth)
            
            logger.info(f"Analysis completed for {target}")
            
            return [
                types.TextContent(
                    type="text",
                    text=response_text
                )
            ]
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in reconnaissance analysis: {error_msg}")
            
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Analysis Failed**\n\n"
                         f"**Error:** {error_msg}\n\n"
                         f"Please check your input data and try again."
                )
            ]
    
    async def _handle_analyze_patterns(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle subdomain pattern analysis"""
        
        try:
            target = arguments.get("target")
            subdomains = arguments.get("subdomains", [])

            if not target or not subdomains:
                raise ValueError("Target and subdomains are required")
            
            logger.info(f"Analyzing patterns for {target} with {len(subdomains)} subdomains")
            
            # Analyze naming patterns
            naming_patterns = await self.pattern_analyzer._analyze_naming_patterns(subdomains, target)
            
            
            
            # Format response
            response_text = f"🔍 **Subdomain Pattern Analysis - {target}**\n\n"
            
            if naming_patterns.conventions:
                response_text += f"📋 **Detected Conventions:**\n"
                for convention in naming_patterns.conventions:
                    response_text += f"• {convention}\n"
                response_text += "\n"
            
            if naming_patterns.predicted_subdomains:
                response_text += f"🎯 **Predicted Subdomains:**\n"
                for pred in naming_patterns.predicted_subdomains[:10]:
                    response_text += f"• {pred}\n"
                response_text += "\n"
            
            if naming_patterns.internal_schemes:
                response_text += f"🏢 **Internal Naming Schemes:**\n"
                for scheme in naming_patterns.internal_schemes:
                    response_text += f"• {scheme}\n"
                response_text += "\n"
            
            if naming_patterns.anomalies:
                response_text += f"⚠️ **Anomalies Detected:**\n"
                for anomaly in naming_patterns.anomalies:
                    response_text += f"• {anomaly}\n"
                response_text += "\n"
            
            response_text += ai_insights
            
            response_text += f"\n🚀 **Next Steps:**\n"
            response_text += f"• Test predicted subdomains for existence\n"
            response_text += f"• Use naming conventions to generate additional permutations\n"
            response_text += f"• Investigate anomalies for potential security issues\n"
            
            return [
                types.TextContent(
                    type="text",
                    text=response_text
                )
            ]
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in pattern analysis: {error_msg}")
            
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Pattern Analysis Failed**\n\n**Error:** {error_msg}"
                )
            ]
    
    async def _handle_analyze_technologies(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle technology stack analysis"""
        
        try:
            technologies = arguments.get("technologies", [])
            live_hosts = arguments.get("live_hosts", [])

            if not technologies:
                raise ValueError("Technologies list is required")
            
            logger.info(f"Analyzing {len(technologies)} technologies")
            
            # Analyze technology stack
            tech_insights = await self.pattern_analyzer._analyze_technology_stack(technologies, live_hosts)
            
            
            
            # Format response
            response_text = f"🔧 **Technology Stack Analysis**\n\n"
            response_text += f"**Stack Summary:** {tech_insights.stack_summary}\n\n"
            
            if tech_insights.vulnerabilities:
                response_text += f"⚠️ **Known Vulnerabilities:**\n"
                for vuln in tech_insights.vulnerabilities:
                    response_text += f"• {vuln}\n"
                response_text += "\n"
            
            if tech_insights.attack_vectors:
                response_text += f"🎯 **Attack Vectors:**\n"
                for vector in tech_insights.attack_vectors:
                    response_text += f"• {vector}\n"
                response_text += "\n"
            
            if tech_insights.testing_tools:
                response_text += f"🛠️ **Recommended Tools:**\n"
                for tool in tech_insights.testing_tools:
                    response_text += f"• {tool}\n"
                response_text += "\n"
            
            response_text += ai_analysis
            
            response_text += f"📋 **Testing Recommendations:**\n"
            response_text += f"• Focus on technology-specific vulnerabilities\n"
            response_text += f"• Check for default configurations and credentials\n"
            response_text += f"• Test for version-specific exploits\n"
            
            return [
                types.TextContent(
                    type="text",
                    text=response_text
                )
            ]
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in technology analysis: {error_msg}")
            
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Technology Analysis Failed**\n\n**Error:** {error_msg}"
                )
            ]
    
    async def _handle_generate_testing_plan(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle testing plan generation"""
        
        try:
            analysis_results = arguments.get("analysis_results", {})
            priority_focus = arguments.get("priority_focus", "coverage")
            time_budget = arguments.get("time_budget", "4 hours")
            
            if not analysis_results:
                raise ValueError("Analysis results are required")
            
            logger.info(f"Generating testing plan with {priority_focus} focus and {time_budget} budget")
            
            # Generate AI recommendations 
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error generating testing plan: {error_msg}")
            
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Testing Plan Generation Failed**\n\n**Error:** {error_msg}"
                )
            ]
    
    async def _handle_check_ai_status(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle pattern analysis status check"""

        response_text = f"🎯 **Pattern Analysis Status**\n\n"
        response_text += f"✅ **Pattern Analysis: Available**\n"
        response_text += f"• Type: Pure pattern-based (no external AI)\n"
        response_text += f"• MCP Architecture: ✅ Optimized\n"
        response_text += f"• Claude Integration: ✅ Ready\n\n"
        response_text += f"🚀 **Available Features:**\n"
        response_text += f"• Intelligent subdomain pattern analysis\n"
        response_text += f"• Technology vulnerability assessment\n"
        response_text += f"• Security-focused recommendations\n"
        response_text += f"• Automated testing plan generation\n"
        response_text += f"• Attack surface mapping\n"
        response_text += f"• Target prioritization\n\n"
        response_text += f"💡 **Note:** Pattern analysis provides structured data for Claude to interpret.\n"
        response_text += f"No external AI API calls are made - pure MCP architecture."
        
        return [
            types.TextContent(
                type="text",
                text=response_text
            )
        ]
    
    def _format_comprehensive_analysis(
        self, 
        analysis: ComprehensiveAnalysis, 
        depth: str
    ) -> str:
        """Format comprehensive analysis results"""
        
        if depth == "quick":
            return self._format_quick_analysis(analysis)
        elif depth == "deep":
            return self._format_deep_analysis(analysis)
        else:
            return self.pattern_analyzer.format_analysis_report(analysis)
    
    def _format_quick_analysis(self, analysis: ComprehensiveAnalysis) -> str:
        """Format quick analysis summary"""
        
        response = f"⚡ **Quick Analysis - {analysis.target}**\n\n"
        
        # Top findings
        if analysis.attack_surface.high_value_targets:
            response += f"🎯 **Top Targets:** {', '.join(analysis.attack_surface.high_value_targets[:3])}\n"
        
        # Key risks
        if analysis.attack_surface.security_risks:
            response += f"⚠️ **Key Risks:** {len(analysis.attack_surface.security_risks)} security concerns\n"
        
        # Technology summary
        response += f"🔧 **Tech Stack:** {analysis.technology_insights.stack_summary}\n"
        
        # Top recommendations
        high_priority = [r for r in analysis.recommendations if r.priority == "high"]
        if high_priority:
            response += f"\n📋 **Immediate Actions:**\n"
            for rec in high_priority[:2]:
                response += f"• {rec.action}\n"
        
        response += f"\n💡 Use 'deep' analysis for detailed insights"
        
        return response
    
    def _format_deep_analysis(self, analysis: ComprehensiveAnalysis) -> str:
        """Format deep analysis with full details"""
        
        # Use the standard report plus additional details
        base_report = self.pattern_analyzer.format_analysis_report(analysis)
        
        # Add deep analysis sections
        deep_sections = f"\n🔬 **Deep Analysis Details**\n\n"
        
        # Naming pattern details
        if analysis.naming_patterns.conventions:
            deep_sections += f"📝 **Naming Pattern Details:**\n"
            for convention in analysis.naming_patterns.conventions:
                deep_sections += f"• {convention}\n"
        
        # Technology vulnerabilities
        if analysis.technology_insights.vulnerabilities:
            deep_sections += f"\n🛡️ **Vulnerability Details:**\n"
            for vuln in analysis.technology_insights.vulnerabilities:
                deep_sections += f"• {vuln}\n"
        
        # All recommendations with details
        deep_sections += f"\n📋 **Complete Recommendation Set:**\n"
        for i, rec in enumerate(analysis.recommendations, 1):
            deep_sections += f"\n**{i}. {rec.priority.upper()} PRIORITY**\n"
            deep_sections += f"Target: {rec.target}\n"
            deep_sections += f"Action: {rec.action}\n"
            deep_sections += f"Tools: {', '.join(rec.tools)}\n"
            deep_sections += f"Rationale: {rec.rationale}\n"
            deep_sections += f"Time: {rec.estimated_time}\n"
        
        return base_report + deep_sections


async def main():
    """Main function to run the MCP server"""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create server instance
    server_instance = BugHoundAnalyzeServer()
    
    # Run the server
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server_instance.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="bughound-analyze",
                server_version="1.0.0",
                capabilities=server_instance.server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )


if __name__ == "__main__":
    asyncio.run(main())