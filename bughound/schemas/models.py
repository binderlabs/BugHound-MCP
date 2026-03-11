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


# ---------------------------------------------------------------------------
# Workspace models
# ---------------------------------------------------------------------------


class WorkspaceState(str, Enum):
    """Pipeline stage the workspace is currently in."""

    INITIALIZED = "INITIALIZED"
    ENUMERATING = "ENUMERATING"
    DISCOVERING = "DISCOVERING"
    ANALYZING = "ANALYZING"
    TESTING = "TESTING"
    VALIDATING = "VALIDATING"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class StageEntry(BaseModel):
    """One entry in the stage_history array."""

    stage: int
    status: str  # "running", "completed", "failed", "skipped"
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None


class WorkspaceStats(BaseModel):
    """Aggregate statistics tracked in metadata."""

    subdomains_found: int = 0
    live_hosts: int = 0
    urls_discovered: int = 0
    findings_total: int = 0
    findings_confirmed: int = 0


class WorkspaceMetadata(BaseModel):
    """System-managed execution state stored as metadata.json."""

    workspace_id: str
    target: str
    target_type: TargetType | None = None
    classification: dict[str, Any] | None = None
    depth: str = "light"
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    current_stage: int = 0
    state: WorkspaceState = WorkspaceState.INITIALIZED
    stage_history: list[StageEntry] = Field(default_factory=list)
    stats: WorkspaceStats = Field(default_factory=WorkspaceStats)
    tool_versions: dict[str, str] = Field(default_factory=dict)


class ScopeConfig(BaseModel):
    """Target scope rules."""

    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class TimeoutConfig(BaseModel):
    """Per-category timeout overrides."""

    passive_recon: int = 60
    active_recon: int = 300
    crawl_per_host: int = 300
    dirfuzz_per_host: int = 600
    nuclei: int = 600


class WorkspaceConfig(BaseModel):
    """User-managed preferences stored as config.json."""

    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    depth: str = "light"
    api_keys: dict[str, str] = Field(default_factory=dict)
    tool_overrides: dict[str, Any] = Field(default_factory=dict)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)


class WorkspaceSummary(BaseModel):
    """Lightweight workspace info for list operations."""

    workspace_id: str
    target: str
    state: WorkspaceState
    depth: str
    created_at: datetime
    updated_at: datetime
    stats: WorkspaceStats


class DataWrapper(BaseModel):
    """Standard JSON wrapper for all data files written to workspace."""

    generated_at: datetime = Field(default_factory=_utcnow)
    generated_by: str = ""
    target: str = ""
    count: int = 0
    data: list[Any] = Field(default_factory=list)
