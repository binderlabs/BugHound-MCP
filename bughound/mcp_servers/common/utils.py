"""
Utility functions for BugHound MCP servers
"""

import re
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_target(target: str) -> bool:
    """
    Validate that a target is safe and properly formatted
    
    Args:
        target: Target domain/IP to validate
        
    Returns:
        bool: True if target is valid
        
    Raises:
        ValueError: If target is invalid or unsafe
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")
    
    # Remove protocol if present
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Basic format validation
    if not re.match(r'^[a-zA-Z0-9.-]+$', target.strip()):
        raise ValueError("Target contains invalid characters")
    
    # Prevent internal/private IPs
    blocked_patterns = [
        r'^localhost$',
        r'^127\.',
        r'^192\.168\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^0\.0\.0\.0$',
        r'^::1$',
        r'^fc00:',
        r'^fe80:'
    ]
    
    for pattern in blocked_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            raise ValueError(f"Internal/private targets not allowed: {target}")
    
    logger.debug(f"Target validated: {target}")
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename
    """
    # Remove path separators and dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    sanitized = re.sub(r'\.\.+', '.', sanitized)
    sanitized = sanitized.strip('. ')
    
    # Ensure it's not empty
    if not sanitized:
        sanitized = "unnamed_file"
    
    return sanitized


def format_tool_result(
    tool_name: str,
    success: bool,
    data: Any = None,
    error: str = None,
    metadata: Dict[str, Any] = None
) -> str:
    """
    Format tool execution results in a consistent way
    
    Args:
        tool_name: Name of the tool that was executed
        success: Whether the tool execution was successful
        data: Tool output data
        error: Error message if unsuccessful
        metadata: Additional metadata about the execution
        
    Returns:
        str: Formatted result string
    """
    if success:
        result = f"✅ {tool_name} completed successfully\n\n"
        
        if data:
            if isinstance(data, dict):
                for key, value in data.items():
                    result += f"**{key}**: {value}\n"
            elif isinstance(data, list):
                result += f"**Results** ({len(data)} items):\n"
                for i, item in enumerate(data, 1):
                    result += f"{i}. {item}\n"
            else:
                result += f"**Result**: {data}\n"
        
        if metadata:
            result += f"\n**Metadata**:\n"
            for key, value in metadata.items():
                result += f"• {key}: {value}\n"
    
    else:
        result = f"❌ {tool_name} failed\n\n"
        if error:
            result += f"**Error**: {error}\n"
        
        if metadata:
            result += f"\n**Debug Info**:\n"
            for key, value in metadata.items():
                result += f"• {key}: {value}\n"
    
    return result


def parse_tool_options(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and normalize tool options from MCP arguments
    
    Args:
        arguments: Raw arguments from MCP call
        
    Returns:
        Dict[str, Any]: Normalized options
    """
    options = {}
    
    # Common option mappings
    option_mappings = {
        'timeout': int,
        'verbose': bool,
        'threads': int,
        'recursive': bool,
        'output_format': str,
        'max_results': int
    }
    
    for key, value in arguments.items():
        if key in option_mappings:
            try:
                options[key] = option_mappings[key](value)
            except (ValueError, TypeError):
                logger.warning(f"Invalid value for {key}: {value}")
                continue
        else:
            options[key] = value
    
    return options