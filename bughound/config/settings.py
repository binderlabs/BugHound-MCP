"""One config source of truth. All settings configurable via environment variables."""

import os
from pathlib import Path

# --- Tool binary discovery ---
# Configurable via BUGHOUND_TOOL_PATHS env var (colon-separated)
_env_paths = os.getenv("BUGHOUND_TOOL_PATHS", "")
_default_paths = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/usr/local/bin",
]
TOOL_PATHS: list[str] = (
    [p.strip() for p in _env_paths.split(":") if p.strip()]
    if _env_paths
    else _default_paths
)

# --- Timeouts (seconds) ---
DEFAULT_TIMEOUT: int = int(os.getenv("BUGHOUND_DEFAULT_TIMEOUT", "120"))

# --- Workspace ---
# Default: ./bughound-workspaces/ in the current working directory
# (where the AI agent CLI is running, not the BugHound source tree)
WORKSPACE_BASE_DIR: Path = Path(
    os.getenv(
        "BUGHOUND_WORKSPACE_DIR",
        str(Path.cwd() / "bughound-workspaces"),
    )
)

# --- Jobs ---
MAX_CONCURRENT_JOBS: int = int(os.getenv("BUGHOUND_MAX_CONCURRENT_JOBS", "5"))
JOB_TIMEOUT: int = int(os.getenv("BUGHOUND_JOB_TIMEOUT", "7200"))  # 2 hour default
JOB_CLEANUP_MAX_AGE_HOURS: int = int(os.getenv("BUGHOUND_JOB_CLEANUP_HOURS", "24"))

# --- Logging ---
LOG_LEVEL: str = os.getenv("BUGHOUND_LOG_LEVEL", "INFO")
