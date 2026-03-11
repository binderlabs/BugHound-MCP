"""
Base MCP Server class for BugHound

Provides common functionality for all BugHound MCP servers.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from mcp.server import Server
import mcp.types as types

logger = logging.getLogger(__name__)


class BaseBugHoundServer(ABC):
    """Abstract base class for BugHound MCP servers"""
    
    def __init__(self, server_name: str, server_version: str = "0.1.0"):
        self.server_name = server_name
        self.server_version = server_version
        self.server = Server(server_name)
        self.tools = {}
        
        logger.info(f"Initializing {server_name} server v{server_version}")
    
    @abstractmethod
    def get_tools(self) -> List[types.Tool]:
        """Return list of tools provided by this server"""
        pass
    
    @abstractmethod
    async def handle_tool_call(
        self, 
        name: str, 
        arguments: Dict[str, Any]
    ) -> List[types.TextContent]:
        """Handle tool execution"""
        pass
    
    def validate_arguments(
        self, 
        arguments: Dict[str, Any], 
        required_fields: List[str]
    ) -> None:
        """Validate that required arguments are present"""
        missing = [field for field in required_fields if field not in arguments]
        if missing:
            raise ValueError(f"Missing required arguments: {', '.join(missing)}")
    
    def create_error_response(self, error_message: str) -> List[types.TextContent]:
        """Create standardized error response"""
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error: {error_message}"
            )
        ]
    
    def create_success_response(
        self, 
        message: str, 
        data: Dict[str, Any] = None
    ) -> List[types.TextContent]:
        """Create standardized success response"""
        response_text = f"✅ {message}"
        
        if data:
            response_text += "\n\nDetails:\n"
            for key, value in data.items():
                response_text += f"• {key}: {value}\n"
        
        return [
            types.TextContent(
                type="text",
                text=response_text
            )
        ]