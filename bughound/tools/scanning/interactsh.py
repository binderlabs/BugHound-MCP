import asyncio
import json
import logging
import os
import tempfile
import uuid
from typing import Dict, Any, List, Optional
from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)

class InteractshTool(BaseTool):
    """
    Wrapper for interactsh-client.
    Generates OOB payloads and polls for interactions (DNS, HTTP, SMTP, etc).
    """
    def __init__(self):
        super().__init__("interactsh-client", timeout=300)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        """
        Execute interactsh-client.
        
        Args:
            target: Not strictly required for the tool but passed by interface.
            options: 
                - action: 'generate' (creates a payload) or 'poll' (checks a session)
                - session_id: required if action is 'poll'
        """
        action = options.get("action", "generate")
        
        if action == "generate":
            return await self._generate_payload()
        elif action == "poll":
            session_id = options.get("session_id")
            if not session_id:
                return ToolResult(success=False, error="session_id required for polling")
            return await self._poll_session(session_id)
        else:
            return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _generate_payload(self) -> ToolResult:
        """Start an interactsh-client instance and extract the generated payload."""
        session_id = str(uuid.uuid4())
        
        # We need a persistent output file for this session to read interactions
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, f"interactsh_{session_id}.json")
        
        # Run interactsh-client in the background, limiting to 1 payload (-n 1) and outputting JSON
        cmd = ["interactsh-client", "-json", "-o", output_file, "-n", "1"]
        
        logger.info(f"Starting interactsh session {session_id}")
        try:
            # We use asyncio.create_subprocess_exec to read the stdout without waiting for it to exit
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stdout line by line until we find the payload URL
            payload_url = None
            if process.stdout:
                while True:
                    try:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=10.0)
                        if not line:
                            break
                        line_str = line.decode('utf-8').strip()
                        
                        # interactsh-client prints the payload like: [INF] Listing 1 payload for OOB Testing
                        # Followed by: [INF] xxxxxxxx.interact.sh
                        if "[INF]" in line_str and "interact.sh" in line_str and "payload" not in line_str.lower():
                            # Extract just the payload domain
                            parts = line_str.split()
                            for part in parts:
                                if "interact.sh" in part or "oast." in part: # Handle custom servers too
                                    payload_url = part.strip()
                                    break
                        if payload_url:
                            break
                    except asyncio.TimeoutError:
                        break
            
            if not payload_url:
                process.terminate()
                return ToolResult(success=False, error="Failed to extract payload URL from interactsh-client")
                
            # Store session tracking info
            self.active_sessions[session_id] = {
                "process": process,
                "output_file": output_file,
                "payload": payload_url
            }
            
            return ToolResult(
                success=True, 
                data={"session_id": session_id, "payload": payload_url},
                raw_output=f"Session created with payload {payload_url}"
            )
            
        except Exception as e:
            logger.error(f"Error starting interactsh: {e}")
            return ToolResult(success=False, error=str(e))

    async def _poll_session(self, session_id: str) -> ToolResult:
        """Check the JSON output file for any recorded interactions."""
        if session_id not in self.active_sessions:
            return ToolResult(success=False, error=f"Session {session_id} not found or expired")
            
        session = self.active_sessions[session_id]
        output_file = session["output_file"]
        
        interactions = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            interactions.append(json.loads(line))
            except Exception as e:
                logger.error(f"Error reading interaction file: {e}")
                
        return ToolResult(
            success=True,
            data={"interactions": interactions, "count": len(interactions)},
            raw_output=f"Found {len(interactions)} interactions"
        )
        
    def cleanup_session(self, session_id: str):
        """Terminate process and clean up files."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            process = session["process"]
            try:
                process.terminate()
            except:
                pass
            
            output_file = session["output_file"]
            try:
                if os.path.exists(output_file):
                    os.remove(output_file)
            except:
                pass
                
            del self.active_sessions[session_id]
            logger.info(f"Cleaned up interactsh session {session_id}")

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # Overridden entirely by execute
        return []

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        # Overridden entirely by execute
        return {}
