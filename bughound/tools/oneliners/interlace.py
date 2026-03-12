"""interlace wrapper — parallel command execution across multiple targets.

Runs a command template in parallel across a target list.
_target_ in the command is replaced with each target.
If the binary is not installed, uses asyncio-based parallel execution.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from bughound.core import tool_runner

BINARY = "interlace"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    targets: list[str],
    command_template: str,
    threads: int = 10,
    timeout: int = 300,
) -> list[str]:
    """Execute command_template in parallel for each target.

    The placeholder _target_ in command_template is replaced with each target.

    Args:
        targets: List of target strings (URLs, domains, IPs).
        command_template: Shell command with _target_ placeholder.
        threads: Number of parallel threads.
        timeout: Max total execution time in seconds.

    Returns list of output lines from all executions.
    """
    if not targets or not command_template:
        return []

    if is_available():
        result = await _run_binary(targets, command_template, threads, timeout)
        if result is not None:
            return result

    return await _python_fallback(targets, command_template, threads, timeout)


async def _run_binary(
    targets: list[str],
    command_template: str,
    threads: int,
    timeout: int,
) -> list[str] | None:
    """Write targets to temp file, run interlace."""
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    # Write targets to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        for t in targets:
            tf.write(t + "\n")
        targets_file = tf.name

    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            "-tL", targets_file,
            "-threads", str(threads),
            "-c", command_template,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return []
    finally:
        Path(targets_file).unlink(missing_ok=True)

    return [
        line.strip()
        for line in stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]


async def _python_fallback(
    targets: list[str],
    command_template: str,
    threads: int,
    timeout: int,
) -> list[str]:
    """Pure-Python parallel execution using asyncio subprocess."""
    results: list[str] = []
    sem = asyncio.Semaphore(threads)

    async def _run_one(target: str) -> None:
        async with sem:
            cmd = command_template.replace("_target_", target)
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout // max(len(targets), 1),
                )
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped:
                        results.append(stripped)
            except (asyncio.TimeoutError, OSError):
                pass

    tasks = [_run_one(t) for t in targets]
    await asyncio.gather(*tasks)

    return results
