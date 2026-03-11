"""Workspace CRUD + lazy directory creation + Pydantic-validated writes.

Central module for all workspace operations.  Every stage reads and writes
data through the functions exposed here — never via direct file I/O.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from bughound.config.settings import WORKSPACE_BASE_DIR
from bughound.schemas.models import (
    DataWrapper,
    ScopeConfig,
    StageEntry,
    WorkspaceConfig,
    WorkspaceMetadata,
    WorkspaceState,
    WorkspaceStats,
    WorkspaceSummary,
)

logger = structlog.get_logger()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Target sanitization
# ---------------------------------------------------------------------------

_UNSAFE_FS = re.compile(r"[^a-z0-9_-]")


def _sanitize_target(target: str) -> str:
    """Convert a target string into a safe filesystem directory name."""
    t = target.strip().lower()
    # Strip protocol
    t = re.sub(r"^https?://", "", t)
    # Strip trailing slashes and paths
    t = t.split("/")[0]
    # Strip port
    t = t.split(":")[0]
    # Replace dots with underscores, collapse multiples
    t = t.replace(".", "_").replace("*", "wildcard")
    # Remove anything else unsafe
    t = _UNSAFE_FS.sub("", t)
    # Collapse repeated underscores, strip leading/trailing
    t = re.sub(r"_+", "_", t).strip("_")
    return t or "unknown"


# ---------------------------------------------------------------------------
# Workspace CRUD
# ---------------------------------------------------------------------------


async def create_workspace(
    target: str,
    depth: str = "light",
) -> WorkspaceMetadata:
    """Create a new workspace. Returns the metadata object.

    Only creates the root directory + metadata.json + config.json.
    All other subdirectories are created lazily when data is written.
    """
    sanitized = _sanitize_target(target)
    short_uuid = uuid.uuid4().hex[:8]
    workspace_id = f"{sanitized}_{short_uuid}"
    ws_dir = WORKSPACE_BASE_DIR / workspace_id

    ws_dir.mkdir(parents=True, exist_ok=True)

    # Build scope from target
    scope_include: list[str] = []
    stripped = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0].split(":")[0]
    if stripped.startswith("*."):
        scope_include.append(stripped)
    else:
        scope_include.append(f"*.{stripped}")
        scope_include.append(stripped)

    metadata = WorkspaceMetadata(
        workspace_id=workspace_id,
        target=target,
        depth=depth,
    )
    config = WorkspaceConfig(
        scope=ScopeConfig(include=scope_include),
        depth=depth,
    )

    # Write both files
    async with aiofiles.open(ws_dir / "metadata.json", "w") as f:
        await f.write(metadata.model_dump_json(indent=2))
    async with aiofiles.open(ws_dir / "config.json", "w") as f:
        await f.write(config.model_dump_json(indent=2))

    logger.info("workspace.created", workspace_id=workspace_id, target=target)
    return metadata


async def get_workspace(workspace_id: str) -> WorkspaceMetadata | None:
    """Load workspace metadata. Returns None if workspace doesn't exist."""
    meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
    if not meta_path.exists():
        return None
    try:
        async with aiofiles.open(meta_path) as f:
            raw = await f.read()
        return WorkspaceMetadata.model_validate_json(raw)
    except Exception as exc:
        logger.error("workspace.read_error", workspace_id=workspace_id, error=str(exc))
        return None


async def get_config(workspace_id: str) -> WorkspaceConfig | None:
    """Load workspace config. Returns None if not found."""
    cfg_path = WORKSPACE_BASE_DIR / workspace_id / "config.json"
    if not cfg_path.exists():
        return None
    try:
        async with aiofiles.open(cfg_path) as f:
            raw = await f.read()
        return WorkspaceConfig.model_validate_json(raw)
    except Exception as exc:
        logger.error("workspace.config_read_error", workspace_id=workspace_id, error=str(exc))
        return None


async def list_workspaces(
    state_filter: WorkspaceState | None = None,
) -> list[WorkspaceSummary]:
    """List all workspaces, optionally filtered by state."""
    base = WORKSPACE_BASE_DIR
    if not base.is_dir():
        return []

    results: list[WorkspaceSummary] = []
    for ws_dir in sorted(base.iterdir()):
        if not ws_dir.is_dir():
            continue
        meta_path = ws_dir / "metadata.json"
        if not meta_path.exists():
            continue
        try:
            raw = meta_path.read_text()
            meta = WorkspaceMetadata.model_validate_json(raw)
            if state_filter and meta.state != state_filter:
                continue
            results.append(
                WorkspaceSummary(
                    workspace_id=meta.workspace_id,
                    target=meta.target,
                    state=meta.state,
                    depth=meta.depth,
                    created_at=meta.created_at,
                    updated_at=meta.updated_at,
                    stats=meta.stats,
                )
            )
        except Exception:
            continue  # skip corrupt workspaces

    # Most recent first
    results.sort(key=lambda w: w.created_at, reverse=True)
    return results


async def delete_workspace(workspace_id: str) -> bool:
    """Delete a workspace and all its data. Returns True if deleted."""
    ws_dir = WORKSPACE_BASE_DIR / workspace_id
    if not ws_dir.is_dir():
        return False
    # Safety: ensure we're deleting inside WORKSPACE_BASE_DIR
    try:
        ws_dir.resolve().relative_to(WORKSPACE_BASE_DIR.resolve())
    except ValueError:
        logger.error("workspace.delete_path_escape", workspace_id=workspace_id)
        return False

    shutil.rmtree(ws_dir)
    logger.info("workspace.deleted", workspace_id=workspace_id)
    return True


def workspace_exists(workspace_id: str) -> bool:
    """Check if a workspace directory exists."""
    return (WORKSPACE_BASE_DIR / workspace_id / "metadata.json").exists()


def workspace_dir(workspace_id: str) -> Path:
    """Return the Path to a workspace directory."""
    return WORKSPACE_BASE_DIR / workspace_id


# ---------------------------------------------------------------------------
# Data I/O
# ---------------------------------------------------------------------------


async def write_data(
    workspace_id: str,
    path: str,
    data: list[str] | list[dict] | list[Any],
    generated_by: str = "",
    target: str = "",
) -> Path:
    """Write data to a workspace file. Creates parent dirs lazily.

    - If path ends with .txt: writes sorted, deduplicated lines
    - If path ends with .json: writes a DataWrapper-validated JSON envelope

    Returns the absolute Path of the written file.
    """
    ws_dir = WORKSPACE_BASE_DIR / workspace_id
    if not ws_dir.is_dir():
        raise FileNotFoundError(f"Workspace '{workspace_id}' does not exist.")

    dest = ws_dir / path
    dest.parent.mkdir(parents=True, exist_ok=True)

    if path.endswith(".txt"):
        lines = sorted(set(str(item).strip() for item in data if str(item).strip()))
        async with aiofiles.open(dest, "w") as f:
            await f.write("\n".join(lines) + "\n" if lines else "")
    else:
        wrapper = DataWrapper(
            generated_by=generated_by,
            target=target,
            count=len(data),
            data=data,
        )
        async with aiofiles.open(dest, "w") as f:
            await f.write(wrapper.model_dump_json(indent=2))

    logger.debug("workspace.write", workspace_id=workspace_id, path=path, count=len(data))
    return dest


async def append_data(
    workspace_id: str,
    path: str,
    new_data: list[str] | list[dict] | list[Any],
    generated_by: str = "",
    target: str = "",
    dedup_key: str | None = None,
) -> Path:
    """Read existing file, merge with new_data, deduplicate, write back.

    For .txt files: union of lines, sorted, deduplicated.
    For .json files: merge data arrays, deduplicate by dedup_key if provided.

    Returns the absolute Path of the written file.
    """
    existing = await read_data(workspace_id, path)

    if path.endswith(".txt"):
        # existing is list[str] or None
        old_lines: list[str] = existing if isinstance(existing, list) else []
        merged = sorted(set(old_lines) | set(str(item).strip() for item in new_data if str(item).strip()))
        return await write_data(workspace_id, path, merged, generated_by, target)
    else:
        # existing is DataWrapper dict or None
        old_items: list[Any] = []
        if isinstance(existing, dict) and "data" in existing:
            old_items = existing["data"]

        all_items = old_items + list(new_data)

        # Deduplicate by key if provided
        if dedup_key and all_items and isinstance(all_items[0], dict):
            seen: set[Any] = set()
            deduped: list[Any] = []
            for item in all_items:
                k = item.get(dedup_key)
                if k not in seen:
                    seen.add(k)
                    deduped.append(item)
            all_items = deduped

        return await write_data(workspace_id, path, all_items, generated_by, target)


async def read_data(
    workspace_id: str,
    path: str,
) -> list[str] | dict[str, Any] | None:
    """Read and parse a workspace data file. Returns None if not found.

    - .txt files: returns list of non-empty lines
    - .json files: returns parsed dict (the full DataWrapper envelope)
    """
    dest = WORKSPACE_BASE_DIR / workspace_id / path
    if not dest.exists():
        return None

    try:
        async with aiofiles.open(dest) as f:
            content = await f.read()

        if path.endswith(".txt"):
            return [line.strip() for line in content.splitlines() if line.strip()]
        else:
            return json.loads(content)
    except Exception as exc:
        logger.error(
            "workspace.read_error",
            workspace_id=workspace_id,
            path=path,
            error=str(exc),
        )
        return None


# ---------------------------------------------------------------------------
# Metadata management
# ---------------------------------------------------------------------------


async def update_metadata(
    workspace_id: str, **kwargs: Any
) -> WorkspaceMetadata | None:
    """Update specific fields in metadata.json. Always bumps updated_at."""
    meta = await get_workspace(workspace_id)
    if meta is None:
        return None

    for key, value in kwargs.items():
        if hasattr(meta, key):
            setattr(meta, key, value)

    meta.updated_at = _utcnow()

    meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
    async with aiofiles.open(meta_path, "w") as f:
        await f.write(meta.model_dump_json(indent=2))

    return meta


async def add_stage_history(
    workspace_id: str,
    stage: int,
    status: str,
) -> None:
    """Append to stage_history in metadata.json."""
    meta = await get_workspace(workspace_id)
    if meta is None:
        return

    entry = StageEntry(stage=stage, status=status)
    # If re-running a stage that's already "running", update it instead of duplicating
    for existing in meta.stage_history:
        if existing.stage == stage and existing.status == "running" and status != "running":
            existing.status = status
            existing.completed_at = _utcnow()
            meta.updated_at = _utcnow()
            meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
            async with aiofiles.open(meta_path, "w") as f:
                await f.write(meta.model_dump_json(indent=2))
            return

    meta.stage_history.append(entry)
    meta.updated_at = _utcnow()

    meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
    async with aiofiles.open(meta_path, "w") as f:
        await f.write(meta.model_dump_json(indent=2))


async def update_stats(workspace_id: str, **kwargs: int) -> None:
    """Update stats counters in metadata.json."""
    meta = await get_workspace(workspace_id)
    if meta is None:
        return

    for key, value in kwargs.items():
        if hasattr(meta.stats, key):
            setattr(meta.stats, key, value)

    meta.updated_at = _utcnow()

    meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
    async with aiofiles.open(meta_path, "w") as f:
        await f.write(meta.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# Scope checking
# ---------------------------------------------------------------------------


async def is_in_scope(workspace_id: str, target: str) -> bool:
    """Check if a target is within the workspace's configured scope.

    Supports wildcard matching: *.example.com matches sub.example.com.
    """
    cfg = await get_config(workspace_id)
    if cfg is None:
        return False

    target_lower = target.strip().lower()
    # Strip protocol and path for matching
    target_lower = re.sub(r"^https?://", "", target_lower).split("/")[0].split(":")[0]

    # Check excludes first
    for pattern in cfg.scope.exclude:
        if fnmatch.fnmatch(target_lower, pattern.lower()):
            return False

    # Check includes
    if not cfg.scope.include:
        return True  # No include rules = everything in scope

    for pattern in cfg.scope.include:
        if fnmatch.fnmatch(target_lower, pattern.lower()):
            return True

    return False
