"""Unified subprocess runner: binary discovery, timeout, sanitization, structured errors.

Every tool wrapper in BugHound uses this module for execution.
Never call asyncio.create_subprocess_exec directly in tool wrappers.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from pathlib import Path

import structlog

from bughound.config.settings import DEFAULT_TIMEOUT, TOOL_PATHS
from bughound.schemas.models import ToolError, ToolErrorType, ToolResult

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Input validation patterns
# ---------------------------------------------------------------------------

# RFC-compliant-ish: labels separated by dots, no trailing dot required
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9*-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

_URL_RE = re.compile(
    r"^https?://"  # scheme
    r"[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;%=-]+"  # rest of URL
    r"$"
)

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Characters that should never appear in any tool argument
_SHELL_META = re.compile(r"[;&|`$(){}!\n\r]")


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


# Override map: tool_name -> absolute path. Set by pre-flight check
# when the correct binary is found in a non-PATH location.
_BINARY_OVERRIDES: dict[str, str] = {}


def find_binary(name: str) -> str | None:
    """Locate a tool binary.

    Search order:
    0. Override map (set by pre-flight tool check)
    1. System PATH (via shutil.which)
    2. Each directory in TOOL_PATHS (from settings / BUGHOUND_TOOL_PATHS env)

    Returns the absolute path to the binary, or None.
    """
    # 0. Override (e.g. Go httpx when Python httpx shadows it)
    if name in _BINARY_OVERRIDES:
        return _BINARY_OVERRIDES[name]

    # 1. System PATH
    path = shutil.which(name)
    if path:
        return path

    # 2. Configured tool directories
    for directory in TOOL_PATHS:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    return None


def is_available(name: str) -> bool:
    """Check whether a tool binary can be found. Never throws."""
    try:
        return find_binary(name) is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------


def validate_domain(value: str) -> str:
    """Validate and return a domain string. Raises ValueError on bad input."""
    value = value.strip().lower()
    if not value:
        raise ValueError("Empty domain")
    if _SHELL_META.search(value):
        raise ValueError(f"Domain contains forbidden characters: {value!r}")
    if not _DOMAIN_RE.match(value):
        raise ValueError(f"Invalid domain format: {value!r}")
    return value


def validate_url(value: str) -> str:
    """Validate and return a URL string. Raises ValueError on bad input."""
    value = value.strip()
    if not value:
        raise ValueError("Empty URL")
    if _SHELL_META.search(value):
        raise ValueError(f"URL contains forbidden characters: {value!r}")
    if not _URL_RE.match(value):
        raise ValueError(f"Invalid URL format: {value!r}")
    return value


def validate_ip(value: str) -> str:
    """Validate and return an IPv4 address string. Raises ValueError on bad input."""
    value = value.strip()
    if not value:
        raise ValueError("Empty IP address")
    if not _IP_RE.match(value):
        raise ValueError(f"Invalid IP format: {value!r}")
    return value


def sanitize_arg(value: str) -> str:
    """Sanitize a generic command argument. Raises ValueError if dangerous."""
    if _SHELL_META.search(value):
        raise ValueError(f"Argument contains forbidden characters: {value!r}")
    return value


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


async def run(
    tool_name: str,
    args: list[str],
    target: str = "",
    timeout: int | None = None,
    cwd: str | None = None,
) -> ToolResult:
    """Execute a tool and return a structured result. Never raises.

    Parameters
    ----------
    tool_name:
        Binary name (e.g. "subfinder"). Looked up via find_binary().
    args:
        Command-line arguments **after** the binary name.
    target:
        The target this invocation is for (used in the result metadata).
    timeout:
        Seconds before the process is killed. Defaults to settings.DEFAULT_TIMEOUT.
    cwd:
        Working directory for the subprocess.

    Returns
    -------
    ToolResult with success=True and raw stdout split into results,
    or success=False with a structured ToolError.
    """
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    # --- Locate binary ---
    binary_path = find_binary(tool_name)
    if binary_path is None:
        err = ToolError(
            error_type=ToolErrorType.NOT_FOUND,
            message=f"Tool '{tool_name}' not found on PATH or in configured tool directories.",
            details={
                "tool": tool_name,
                "searched_paths": TOOL_PATHS,
                "install_hint": _install_hint(tool_name),
            },
        )
        return err.to_result(tool=tool_name, target=target)

    cmd = [binary_path, *args]
    log = logger.bind(tool=tool_name, target=target)
    log.info("tool.start", cmd=_redact_cmd(cmd))
    start = time.monotonic()

    # --- Execute ---
    # Launch in a new process group so we can kill the entire tree on timeout.
    # Some tools (arjun, sqlmap) spawn many worker processes that hold pipes
    # open after the main process dies, causing proc.communicate() to hang.
    import os as _os
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,  # isolates process group
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # Kill the whole process group (arjun workers, sqlmap threads, etc.)
            import signal as _signal
            try:
                _os.killpg(_os.getpgid(proc.pid), _signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

            # Hard 3s cap for collecting any remaining output — don't let
            # orphan children hang us here.
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=3,
                )
            except Exception:
                stdout_bytes, stderr_bytes = b"", b""

            elapsed = time.monotonic() - start
            partial_lines = _decode(stdout_bytes).splitlines()
            err = ToolError(
                error_type=ToolErrorType.TIMEOUT,
                message=f"Tool '{tool_name}' timed out after {timeout}s.",
                details={
                    "timeout_seconds": timeout,
                    "partial_output_lines": len(partial_lines),
                },
            )
            result = err.to_result(tool=tool_name, target=target)
            result.execution_time_seconds = round(elapsed, 2)
            # Include partial results so callers can use whatever was gathered
            result.results = partial_lines
            result.raw_output_lines = len(partial_lines)
            result.result_count = len(partial_lines)
            log.warning("tool.timeout", elapsed=round(elapsed, 2), partial_lines=len(partial_lines))
            return result

    except FileNotFoundError:
        # Binary vanished between find_binary() and exec
        err = ToolError(
            error_type=ToolErrorType.NOT_FOUND,
            message=f"Tool '{tool_name}' binary disappeared before execution.",
            details={"binary_path": binary_path},
        )
        return err.to_result(tool=tool_name, target=target)
    except OSError as exc:
        err = ToolError(
            error_type=ToolErrorType.EXECUTION,
            message=f"OS error launching '{tool_name}': {exc}",
            details={"exception": str(exc)},
        )
        return err.to_result(tool=tool_name, target=target)

    elapsed = time.monotonic() - start
    stdout = _decode(stdout_bytes)
    stderr = _decode(stderr_bytes)

    # --- Non-zero exit code ---
    if proc.returncode != 0:
        err = ToolError(
            error_type=ToolErrorType.EXECUTION,
            message=f"Tool '{tool_name}' exited with code {proc.returncode}.",
            details={
                "exit_code": proc.returncode,
                "stderr": stderr[:2000],  # cap for sanity
            },
        )
        result = err.to_result(tool=tool_name, target=target)
        result.execution_time_seconds = round(elapsed, 2)
        # Still attach stdout -- some tools write useful output even on error
        lines = [l for l in stdout.splitlines() if l.strip()]
        result.results = lines
        result.raw_output_lines = len(lines)
        result.result_count = len(lines)
        if stderr:
            result.errors.append(stderr[:2000])
        log.warning("tool.nonzero_exit", code=proc.returncode, elapsed=round(elapsed, 2))
        return result

    # --- Success ---
    lines = [l for l in stdout.splitlines() if l.strip()]
    warnings: list[str] = []
    if stderr.strip():
        warnings.append(stderr[:2000])

    log.info("tool.done", elapsed=round(elapsed, 2), lines=len(lines))
    return ToolResult(
        tool=tool_name,
        target=target,
        success=True,
        execution_time_seconds=round(elapsed, 2),
        result_count=len(lines),
        results=lines,
        raw_output_lines=len(lines),
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode(data: bytes) -> str:
    """Best-effort decode, replacing errors."""
    return data.decode("utf-8", errors="replace")


def _redact_cmd(cmd: list[str]) -> list[str]:
    """Return command list safe for logging (truncate long args)."""
    return [a if len(a) < 200 else a[:197] + "..." for a in cmd]


_INSTALL_HINTS: dict[str, str] = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install -v github.com/tomnomnom/waybackurls@latest",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest",
    "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
    "subjack": "go install -v github.com/haccer/subjack@latest",
    "findomain": "apt install findomain  # or cargo install findomain",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "knockpy": "pip install knockpy",
    "wafw00f": "pip install wafw00f",
    "sqlmap": "apt install sqlmap",
    "nmap": "apt install nmap",
    "trufflehog": "go install -v github.com/trufflesecurity/trufflehog@latest",
    "arjun": "pip install arjun",
    "interactsh-client": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "qsreplace": "go install github.com/tomnomnom/qsreplace@latest",
    "kxss": "go install github.com/Emoe/kxss@latest",
    "gf": "go install github.com/tomnomnom/gf@latest",
    "uro": "pip install uro",
    "unfurl": "go install github.com/tomnomnom/unfurl@latest",
    "anew": "go install github.com/tomnomnom/anew@latest",
    "Gxss": "go install github.com/KathanP19/Gxss@latest",
    "bhedak": "pipx install bhedak",
    "urldedupe": "git clone https://github.com/ameenmaali/urldedupe && cd urldedupe && cmake . && make",
    "interlace": "pipx install git+https://github.com/codingo/Interlace.git",
}


def _install_hint(tool_name: str) -> str:
    return _INSTALL_HINTS.get(tool_name, f"Check the tool's documentation for installation instructions.")
