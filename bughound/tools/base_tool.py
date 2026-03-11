from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass
import asyncio
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    raw_output: Optional[str] = None


class BaseTool(ABC):
    def __init__(self, name: str, timeout: int = 300):
        self.name = name
        self.timeout = timeout
    
    @abstractmethod
    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        pass
    
    @abstractmethod
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        pass
    
    async def _run_command(self, cmd: list[str], cwd: str = None) -> str:
        """Execute a shell command asynchronously"""
        try:
            # Add ~/go/bin to PATH
            env = os.environ.copy()
            go_bin = os.path.expanduser("~/go/bin")
            if go_bin not in env["PATH"]:
                env["PATH"] = f"{go_bin}:{env['PATH']}"

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                # Some tools write to stderr but succeed (like subfinder)
                # We'll log stderr but return stdout if it exists
                if stderr:
                    logger.warning(f"Tool {self.name} stderr: {stderr.decode()}")
                
                if not stdout and stderr:
                    raise Exception(f"Command failed with code {process.returncode}: {stderr.decode()}")
            
            return stdout.decode()
            
        except Exception as e:
            logger.error(f"Error executing {self.name}: {e}")
            raise Exception(f"Command timed out after {self.timeout}s")
    
    def _build_command(self, target: str, options: Dict[str, Any]) -> list[str]:
        raise NotImplementedError("Subclasses must implement _build_command")