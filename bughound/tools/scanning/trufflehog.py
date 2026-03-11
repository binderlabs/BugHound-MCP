from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class TruffleHogTool(BaseTool):
    def __init__(self):
        super().__init__("trufflehog", timeout=600)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            # TruffleHog can scan git, filesystem, or s3. 
            # For web recon, we usually want to scan specific JS files or a git repo.
            # If target starts with http, we might need 'filesystem' mode after downloading, 
            # or use 'git' if it's a git repo.
            # For simplicity in Phase 3, we assume target is a URL to a git repo OR we are scanning a local directory (the loot).
            # Let's assume we are scanning the 'web' directory of the workspace.
            
            # If target is a directory path
            if os.path.isdir(target):
                cmd = self._build_command(target, options)
                raw_output = await self._run_command(cmd)
                parsed_data = self._parse_output(raw_output)
                return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
            
            # If target is a URL (git)
            elif target.endswith(".git"):
                cmd = ["trufflehog", "git", target, "--json"]
                raw_output = await self._run_command(cmd)
                parsed_data = self._parse_output(raw_output)
                return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
                
            else:
                return ToolResult(success=False, error="TruffleHog target must be a directory or .git URL")

        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # trufflehog filesystem /path/to/dir --json
        cmd = ["trufflehog", "filesystem", target, "--json"]
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        secrets = []
        for line in raw_output.splitlines():
            try:
                if not line.strip(): continue
                entry = json.loads(line)
                # TruffleHog JSON is verbose
                secrets.append({
                    "detector": entry.get("DetectorName"),
                    "decoder": entry.get("DecoderName"),
                    "raw": entry.get("Raw"),
                    "source": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file")
                })
            except json.JSONDecodeError:
                continue
                
        return {
            "secrets": secrets,
            "count": len(secrets)
        }
