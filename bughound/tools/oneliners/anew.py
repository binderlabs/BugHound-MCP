"""anew wrapper — append new unique lines to a file.

If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from bughound.core import tool_runner

BINARY = "anew"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    lines: list[str], output_file: str | Path, timeout: int = 30,
) -> list[str]:
    """Append only new unique lines to output_file.

    Returns the list of newly added lines.
    """
    if not lines:
        return []

    output_file = Path(output_file)

    if is_available():
        result = await _run_binary(lines, output_file, timeout)
        if result is not None:
            return result

    return _python_fallback(lines, output_file)


async def _run_binary(
    lines: list[str], output_file: Path, timeout: int,
) -> list[str] | None:
    """Pipe lines into anew binary."""
    stdin_data = "\n".join(lines).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    proc = await asyncio.create_subprocess_exec(
        binary_path, str(output_file),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None

    return [line.strip() for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]


def _python_fallback(lines: list[str], output_file: Path) -> list[str]:
    """Pure-Python anew: read existing, append new unique lines."""
    existing: set[str] = set()
    if output_file.exists():
        existing = set(output_file.read_text().splitlines())

    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and stripped not in existing:
            existing.add(stripped)
            new_lines.append(stripped)

    if new_lines:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("a") as f:
            for line in new_lines:
                f.write(line + "\n")

    return new_lines
