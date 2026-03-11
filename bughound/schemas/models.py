"""All Pydantic models: workspace metadata, config, findings, scan plan, tool output."""

from __future__ import annotations

from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Job manager models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, Enum):
    """Lifecycle states for an async job."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class JobRecord(BaseModel):
    """Persistent state for a single background job."""

    job_id: str
    workspace_id: str
    job_type: str
    target: str
    status: JobStatus = JobStatus.PENDING
    progress_pct: int = Field(default=0, ge=0, le=100)
    message: str = ""
    current_module: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None
    result_summary: dict[str, Any] | None = None
    error: str | None = None
