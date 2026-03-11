"""All Pydantic models: workspace metadata, config, findings, scan plan, tool output."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Tool runner models
# ---------------------------------------------------------------------------


class ToolErrorType(str, Enum):
    """Categories of tool execution failure."""

    NOT_FOUND = "tool_not_found"
    TIMEOUT = "tool_timeout"
    EXECUTION = "tool_execution_error"
    PARSE = "tool_parse_error"
    VALIDATION = "input_validation_error"


class ToolError(BaseModel):
    """Structured error returned when a tool fails."""

    error_type: ToolErrorType
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

    def to_result(self, tool: str, target: str) -> ToolResult:
        """Wrap this error in a ToolResult for uniform return."""
        return ToolResult(
            tool=tool,
            target=target,
            success=False,
            error=self,
        )


class ToolResult(BaseModel):
    """Structured result returned by every tool execution."""

    tool: str
    target: str
    success: bool = True
    execution_time_seconds: float = 0.0
    result_count: int = 0
    results: list[Any] = Field(default_factory=list)
    raw_output_lines: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: ToolError | None = None


# ---------------------------------------------------------------------------
# Target classification models  (used by Stage 0, defined here for reuse)
# ---------------------------------------------------------------------------


class TargetType(str, Enum):
    """How a user-supplied target is classified."""

    BROAD_DOMAIN = "broad_domain"
    SINGLE_HOST = "single_host"
    SINGLE_ENDPOINT = "single_endpoint"
    URL_LIST = "url_list"
