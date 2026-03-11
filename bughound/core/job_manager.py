"""Async job lifecycle: create, poll, cancel, cleanup, timeout.

Singleton JobManager tracks all background jobs across the server.
Jobs are persisted to {workspace}/jobs/{job_id}.json and indexed
in-memory for O(1) status lookups.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Coroutine
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from bughound.config.settings import (
    JOB_CLEANUP_MAX_AGE_HOURS,
    JOB_TIMEOUT,
    MAX_CONCURRENT_JOBS,
    WORKSPACE_BASE_DIR,
)
from bughound.schemas.models import JobRecord, JobStatus

logger = structlog.get_logger()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class JobManager:
    """Manages async background jobs with persistence and indexed lookup.

    Usage::

        jm = JobManager()
        job_id = await jm.create_job("ws_abc", "enumerate_deep", "example.com")
        await jm.start_job(job_id, my_coroutine(job_id))
        status = await jm.get_status(job_id)
        await jm.cancel_job(job_id)
    """

    def __init__(self) -> None:
        # In-memory index: job_id -> JobRecord
        self._jobs: dict[str, JobRecord] = {}
        # In-memory index: job_id -> workspace_id (for file path resolution)
        self._job_workspace: dict[str, str] = {}
        # Running asyncio tasks: job_id -> Task
        self._tasks: dict[str, asyncio.Task] = {}
        # Timeout watchdog tasks: job_id -> Task
        self._watchdogs: dict[str, asyncio.Task] = {}
        # Serialize file writes per job
        self._write_lock = asyncio.Lock()
        self._initialized = False

    # ------------------------------------------------------------------
    # Initialization: rebuild index from disk on first use
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        """Rebuild in-memory index from existing job files on disk."""
        if self._initialized:
            return
        self._initialized = True
        await self._rebuild_index()

    async def _rebuild_index(self) -> None:
        """Scan workspace directories for existing job files and load them."""
        base = WORKSPACE_BASE_DIR
        if not base.is_dir():
            return

        count = 0
        for ws_dir in base.iterdir():
            if not ws_dir.is_dir():
                continue
            jobs_dir = ws_dir / "jobs"
            if not jobs_dir.is_dir():
                continue
            for job_file in jobs_dir.glob("job_*.json"):
                try:
                    raw = job_file.read_text()
                    record = JobRecord.model_validate_json(raw)
                    self._jobs[record.job_id] = record
                    self._job_workspace[record.job_id] = record.workspace_id
                    count += 1
                except Exception as exc:
                    logger.warning(
                        "job.rebuild_skip",
                        file=str(job_file),
                        error=str(exc),
                    )
        if count:
            logger.info("job.index_rebuilt", job_count=count)

    # ------------------------------------------------------------------
    # Core lifecycle
    # ------------------------------------------------------------------

    async def create_job(
        self,
        workspace_id: str,
        job_type: str,
        target: str,
    ) -> str:
        """Create a new job record. Returns the job_id.

        Raises RuntimeError if max concurrent running jobs is reached.
        """
        await self._ensure_initialized()

        running = sum(
            1 for j in self._jobs.values() if j.status == JobStatus.RUNNING
        )
        if running >= MAX_CONCURRENT_JOBS:
            raise RuntimeError(
                f"Max concurrent jobs ({MAX_CONCURRENT_JOBS}) reached. "
                f"Wait for a job to finish or cancel one."
            )

        short_uuid = uuid.uuid4().hex[:8]
        job_id = f"job_{job_type}_{short_uuid}"

        record = JobRecord(
            job_id=job_id,
            workspace_id=workspace_id,
            job_type=job_type,
            target=target,
            status=JobStatus.PENDING,
            message="Job created, waiting to start.",
        )

        self._jobs[job_id] = record
        self._job_workspace[job_id] = workspace_id
        await self._persist(job_id)

        logger.info("job.created", job_id=job_id, job_type=job_type, target=target)
        return job_id

    async def start_job(
        self,
        job_id: str,
        coro: Coroutine[Any, Any, Any],
        timeout: int | None = None,
    ) -> None:
        """Spawn an asyncio task for the job coroutine.

        The coroutine should call update_progress / complete_job / fail_job
        as it runs.  If it raises, the job is automatically marked FAILED.
        """
        record = self._get_record(job_id)
        if timeout is None:
            timeout = JOB_TIMEOUT

        record.status = JobStatus.RUNNING
        record.message = "Job started."
        record.updated_at = _utcnow()
        await self._persist(job_id)

        # Wrap the coroutine to catch exceptions
        async def _wrapper() -> None:
            try:
                await coro
            except asyncio.CancelledError:
                # Handled by cancel_job or watchdog
                raise
            except Exception as exc:
                logger.error("job.unhandled_error", job_id=job_id, error=str(exc))
                await self.fail_job(job_id, str(exc))

        task = asyncio.create_task(_wrapper(), name=job_id)
        self._tasks[job_id] = task
        task.add_done_callback(lambda t: self._on_task_done(job_id, t))

        # Start timeout watchdog
        watchdog = asyncio.create_task(
            self._timeout_watchdog(job_id, timeout), name=f"{job_id}_watchdog"
        )
        self._watchdogs[job_id] = watchdog

        logger.info("job.started", job_id=job_id, timeout=timeout)

    async def update_progress(
        self,
        job_id: str,
        progress_pct: int,
        message: str = "",
        current_module: str = "",
    ) -> None:
        """Update job progress. Safe to call from the running coroutine."""
        record = self._get_record(job_id)
        record.progress_pct = max(0, min(100, progress_pct))
        if message:
            record.message = message
        if current_module:
            record.current_module = current_module
        record.updated_at = _utcnow()
        await self._persist(job_id)

    async def complete_job(
        self,
        job_id: str,
        result_summary: dict[str, Any] | None = None,
    ) -> None:
        """Mark job as successfully completed."""
        record = self._get_record(job_id)
        record.status = JobStatus.COMPLETED
        record.progress_pct = 100
        record.message = "Job completed."
        record.completed_at = _utcnow()
        record.updated_at = _utcnow()
        record.result_summary = result_summary
        await self._persist(job_id)
        self._cancel_watchdog(job_id)
        logger.info("job.completed", job_id=job_id)

    async def fail_job(self, job_id: str, error_message: str) -> None:
        """Mark job as failed."""
        record = self._get_record(job_id)
        # Don't overwrite terminal states (e.g. CANCELLED, TIMED_OUT)
        if record.status in (
            JobStatus.CANCELLED,
            JobStatus.TIMED_OUT,
            JobStatus.COMPLETED,
        ):
            return
        record.status = JobStatus.FAILED
        record.error = error_message
        record.message = f"Job failed: {error_message[:200]}"
        record.completed_at = _utcnow()
        record.updated_at = _utcnow()
        await self._persist(job_id)
        self._cancel_watchdog(job_id)
        logger.error("job.failed", job_id=job_id, error=error_message[:200])

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job. Returns True if cancellation was issued."""
        record = self._get_record(job_id)
        if record.status not in (JobStatus.PENDING, JobStatus.RUNNING):
            return False

        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()

        record.status = JobStatus.CANCELLED
        record.message = "Job cancelled by user."
        record.completed_at = _utcnow()
        record.updated_at = _utcnow()
        await self._persist(job_id)
        self._cancel_watchdog(job_id)
        logger.info("job.cancelled", job_id=job_id)
        return True

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def get_status(self, job_id: str) -> dict[str, Any] | None:
        """Return job status dict. O(1) via in-memory index. Returns None if not found."""
        await self._ensure_initialized()
        record = self._jobs.get(job_id)
        if record is None:
            return None
        return record.model_dump(mode="json")

    async def list_jobs(
        self,
        workspace_id: str | None = None,
        status_filter: JobStatus | None = None,
    ) -> list[dict[str, Any]]:
        """List jobs, optionally filtered by workspace and/or status."""
        await self._ensure_initialized()
        results = []
        for record in self._jobs.values():
            if workspace_id and record.workspace_id != workspace_id:
                continue
            if status_filter and record.status != status_filter:
                continue
            results.append(record.model_dump(mode="json"))
        # Most recent first
        results.sort(key=lambda j: j["created_at"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def cleanup_old_jobs(
        self, max_age_hours: int | None = None
    ) -> int:
        """Remove completed/failed/cancelled job records older than threshold.

        Returns the number of jobs cleaned up.
        """
        await self._ensure_initialized()
        if max_age_hours is None:
            max_age_hours = JOB_CLEANUP_MAX_AGE_HOURS

        cutoff = _utcnow() - timedelta(hours=max_age_hours)
        terminal = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.TIMED_OUT}
        to_remove: list[str] = []

        for job_id, record in self._jobs.items():
            if record.status not in terminal:
                continue
            finished = record.completed_at or record.updated_at
            if finished < cutoff:
                to_remove.append(job_id)

        for job_id in to_remove:
            # Delete file
            path = self._job_path(job_id)
            if path and path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
            self._jobs.pop(job_id, None)
            self._job_workspace.pop(job_id, None)
            self._tasks.pop(job_id, None)

        if to_remove:
            logger.info("job.cleanup", removed=len(to_remove))
        return len(to_remove)

    # ------------------------------------------------------------------
    # Timeout watchdog
    # ------------------------------------------------------------------

    async def _timeout_watchdog(self, job_id: str, timeout: int) -> None:
        """Wait for timeout seconds, then kill the job if still running."""
        try:
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            return  # Watchdog cancelled because job finished normally

        record = self._jobs.get(job_id)
        if record is None or record.status != JobStatus.RUNNING:
            return

        # Kill the task
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()

        record.status = JobStatus.TIMED_OUT
        record.message = f"Job timed out after {timeout}s."
        record.error = f"Timeout: exceeded {timeout}s limit."
        record.completed_at = _utcnow()
        record.updated_at = _utcnow()
        await self._persist(job_id)
        logger.warning("job.timed_out", job_id=job_id, timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_record(self, job_id: str) -> JobRecord:
        """Get a job record or raise KeyError."""
        record = self._jobs.get(job_id)
        if record is None:
            raise KeyError(f"Job '{job_id}' not found.")
        return record

    def _on_task_done(self, job_id: str, task: asyncio.Task) -> None:
        """Callback when an asyncio task finishes (success, error, or cancel)."""
        self._tasks.pop(job_id, None)
        # If task was cancelled but status wasn't updated yet (e.g. by watchdog),
        # we don't overwrite — the watchdog/cancel_job already set the status.

    def _cancel_watchdog(self, job_id: str) -> None:
        """Cancel the timeout watchdog for a job."""
        watchdog = self._watchdogs.pop(job_id, None)
        if watchdog and not watchdog.done():
            watchdog.cancel()

    def _job_path(self, job_id: str) -> Path | None:
        """Resolve the filesystem path for a job's JSON file."""
        ws_id = self._job_workspace.get(job_id)
        if ws_id is None:
            return None
        return WORKSPACE_BASE_DIR / ws_id / "jobs" / f"{job_id}.json"

    async def _persist(self, job_id: str) -> None:
        """Write job record to disk. Creates directories lazily."""
        record = self._jobs.get(job_id)
        if record is None:
            return

        path = self._job_path(job_id)
        if path is None:
            return

        async with self._write_lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = record.model_dump_json(indent=2)
            async with aiofiles.open(path, "w") as f:
                await f.write(data)
