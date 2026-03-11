"""Single BugHound MCP server. All tools registered here."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from bughound.core import target_classifier, workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import WorkspaceState
from bughound.stages import discover as stage_discover
from bughound.stages import enumerate as stage_enumerate

# Shared job manager instance (lives for server lifetime)
_job_manager = JobManager()

mcp = FastMCP("bughound")


# ---------------------------------------------------------------------------
# Stage 0: Initialize + Workspace management
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_init",
    description=(
        "Initialize a new BugHound workspace for a target. Stage 0: classifies "
        "the target (broad domain, single host, endpoint, or URL list), creates "
        "a workspace, and returns which pipeline stages to run. Always call this "
        "first before any other bughound tool. Sync."
    ),
)
async def bughound_init(target: str, depth: str = "light") -> str:
    """Classify target and create workspace."""
    try:
        classification = target_classifier.classify(target, depth)
    except ValueError as exc:
        return json.dumps({
            "status": "error",
            "error_type": "invalid_input",
            "message": str(exc),
        })

    meta = await workspace.create_workspace(target, depth)

    # Store classification in workspace metadata
    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )

    # Record Stage 0 as completed
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")

    return json.dumps({
        "status": "success",
        "message": (
            f"Workspace created for {target} "
            f"(classified as {classification.target_type.value})."
        ),
        "workspace_id": meta.workspace_id,
        "data": {
            "target_type": classification.target_type.value,
            "normalized_targets": classification.normalized_targets,
            "stages_to_run": classification.stages_to_run,
            "skip_reasons": classification.skip_reasons,
            "depth": depth,
        },
        "next_step": _suggest_next(classification.stages_to_run),
    })


@mcp.tool(
    name="bughound_workspace_list",
    description=(
        "List all BugHound workspaces. Optionally filter by state "
        "(INITIALIZED, ENUMERATING, DISCOVERING, ANALYZING, TESTING, "
        "VALIDATING, COMPLETED, ARCHIVED). Sync."
    ),
)
async def bughound_workspace_list(state: str = "") -> str:
    """List workspaces with optional state filter."""
    state_filter = None
    if state:
        try:
            state_filter = WorkspaceState(state.upper())
        except ValueError:
            valid = ", ".join(s.value for s in WorkspaceState)
            return json.dumps({
                "status": "error",
                "error_type": "invalid_input",
                "message": f"Invalid state '{state}'. Valid states: {valid}",
            })

    workspaces = await workspace.list_workspaces(state_filter)
    summaries = [ws.model_dump(mode="json") for ws in workspaces]

    return json.dumps({
        "status": "success",
        "message": f"Found {len(summaries)} workspace(s).",
        "data": summaries,
    })


@mcp.tool(
    name="bughound_workspace_get",
    description=(
        "Get full details of a BugHound workspace including metadata, "
        "config, current stage, and stats. Requires workspace_id from "
        "bughound_init or bughound_workspace_list. Sync."
    ),
)
async def bughound_workspace_get(workspace_id: str) -> str:
    """Get workspace metadata and config."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return json.dumps({
            "status": "error",
            "error_type": "not_found",
            "message": (
                f"Workspace '{workspace_id}' not found. "
                "Run bughound_init first to create a workspace."
            ),
        })

    cfg = await workspace.get_config(workspace_id)

    return json.dumps({
        "status": "success",
        "message": f"Workspace {workspace_id} ({meta.target})",
        "data": {
            "metadata": meta.model_dump(mode="json"),
            "config": cfg.model_dump(mode="json") if cfg else None,
        },
    })


@mcp.tool(
    name="bughound_workspace_delete",
    description=(
        "Delete a BugHound workspace and all its data. This is irreversible. "
        "Requires workspace_id. Sync."
    ),
)
async def bughound_workspace_delete(workspace_id: str) -> str:
    """Delete a workspace."""
    if not workspace.workspace_exists(workspace_id):
        return json.dumps({
            "status": "error",
            "error_type": "not_found",
            "message": f"Workspace '{workspace_id}' not found.",
        })

    deleted = await workspace.delete_workspace(workspace_id)
    if deleted:
        return json.dumps({
            "status": "success",
            "message": f"Workspace '{workspace_id}' deleted.",
        })

    return json.dumps({
        "status": "error",
        "error_type": "execution_failed",
        "message": f"Failed to delete workspace '{workspace_id}'.",
    })


# ---------------------------------------------------------------------------
# Stage 1: Enumerate
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_enumerate",
    description=(
        "Discover subdomains for a broad domain target. Stage 1: runs passive "
        "subdomain sources (subfinder, assetfinder, findomain, crt.sh) in parallel, "
        "resolves DNS, detects wildcards, and analyzes naming patterns. Requires "
        "bughound_init first. Auto-skips for non-domain targets. Sync, ~30-60s."
    ),
)
async def bughound_enumerate(workspace_id: str) -> str:
    """Run light subdomain enumeration."""
    result = await stage_enumerate.enumerate_light(workspace_id)
    return json.dumps(result)


@mcp.tool(
    name="bughound_enumerate_deep",
    description=(
        "Deep subdomain enumeration as a background job. Stage 1 deep mode: "
        "runs all passive sources plus active bruteforce and permutation fuzzing "
        "if tools are available. Requires bughound_init first. Returns job_id — "
        "poll with bughound_job_status. Async, 5-15 minutes."
    ),
)
async def bughound_enumerate_deep(workspace_id: str) -> str:
    """Start deep enumeration as a background job."""
    result = await stage_enumerate.enumerate_deep(workspace_id, _job_manager)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Stage 2: Discover
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_discover",
    description=(
        "Discover full attack surface: probe live hosts, fingerprint tech, detect "
        "WAF/CDN, crawl URLs, analyze JavaScript for secrets and hidden endpoints, "
        "harvest parameters, generate intelligence flags. Sync for single hosts "
        "(~60s), async job for broad domains. Requires bughound_init first; "
        "for broad domains also requires bughound_enumerate."
    ),
)
async def bughound_discover(workspace_id: str) -> str:
    """Run Stage 2 discovery."""
    result = await stage_discover.discover(workspace_id, _job_manager)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_job_status",
    description=(
        "Check the status of an async background job. Returns progress percentage, "
        "current module, status, and result summary if completed. Sync."
    ),
)
async def bughound_job_status(job_id: str) -> str:
    """Poll job status."""
    status = await _job_manager.get_status(job_id)
    if status is None:
        return json.dumps({
            "status": "error",
            "error_type": "not_found",
            "message": f"Job '{job_id}' not found.",
        })
    return json.dumps({
        "status": "success",
        "data": status,
    })


@mcp.tool(
    name="bughound_job_results",
    description=(
        "Get results of a completed async job. Returns the workspace data "
        "written by the job. Requires a completed job_id. Sync."
    ),
)
async def bughound_job_results(job_id: str) -> str:
    """Get completed job results."""
    status = await _job_manager.get_status(job_id)
    if status is None:
        return json.dumps({
            "status": "error",
            "error_type": "not_found",
            "message": f"Job '{job_id}' not found.",
        })

    if status["status"] not in ("COMPLETED", "FAILED", "TIMED_OUT"):
        return json.dumps({
            "status": "error",
            "error_type": "invalid_input",
            "message": (
                f"Job '{job_id}' is still {status['status']}. "
                "Wait for completion or poll with bughound_job_status."
            ),
        })

    return json.dumps({
        "status": "success",
        "data": {
            "job_status": status["status"],
            "result_summary": status.get("result_summary"),
            "error": status.get("error"),
            "workspace_id": status.get("workspace_id"),
        },
    })


@mcp.tool(
    name="bughound_job_cancel",
    description=(
        "Cancel a running async job. Returns confirmation. Sync."
    ),
)
async def bughound_job_cancel(job_id: str) -> str:
    """Cancel a background job."""
    try:
        cancelled = await _job_manager.cancel_job(job_id)
    except KeyError:
        return json.dumps({
            "status": "error",
            "error_type": "not_found",
            "message": f"Job '{job_id}' not found.",
        })

    if cancelled:
        return json.dumps({
            "status": "success",
            "message": f"Job '{job_id}' cancelled.",
        })

    return json.dumps({
        "status": "error",
        "error_type": "invalid_input",
        "message": f"Job '{job_id}' is not running (cannot cancel).",
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _suggest_next(stages: list[int]) -> str:
    """Suggest the next tool to call based on stages_to_run."""
    if 1 in stages:
        return "Call bughound_enumerate to discover subdomains."
    if 2 in stages:
        return "Call bughound_discover to probe and discover the attack surface."
    return "Call the next stage tool in the pipeline."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the BugHound MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
