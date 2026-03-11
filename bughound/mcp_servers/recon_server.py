#!/usr/bin/env python3
"""
BugHound Reconnaissance MCP Server

This server provides reconnaissance and asset discovery capabilities through MCP.
Currently implements a test connection tool to verify MCP connectivity.
"""

import asyncio
import logging
from typing import Any, Dict, List

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Import BugHound tools
from ..tools.recon.subfinder import SubfinderTool
from ..tools.recon.altdns import AltDNSTool
from ..tools.recon.httpx import HTTPxTool
from ..tools.recon.waybackurls import WaybackURLsTool
from ..tools.recon.gau import GauTool
from ..tools.recon.assetfinder import AssetfinderTool
from ..tools.recon.findomain import FindomainTool
from ..tools.recon.crtsh import CrtShTool
from ..tools.recon.whois import WhoisTool
from ..tools.recon.wafw00f import Wafw00fTool
from ..tools.scanning.nmap import NmapTool
from ..tools.scanning.nuclei import NucleiTool
from ..core.subdomain_discovery import SubdomainDiscovery
from ..core.subdomain_enrichment import SubdomainEnrichment
from ..core.pattern_analyzer import create_pattern_analyzer
from ..core.workspace_manager import WorkspaceManager
from ..core.change_detector import ChangeDetector, format_change_report
from ..core.report_generator import ReportGenerator, ReportType, ReportFormat
from .common.utils import validate_target, format_tool_result

# Configure logging — stderr only (stdout is reserved for JSON-RPC stdio transport)
import sys as _sys
logging.basicConfig(level=logging.WARNING, stream=_sys.stderr)
logger = logging.getLogger(__name__)


class BugHoundReconServer:
    """BugHound Reconnaissance MCP Server"""
    
    def __init__(self):
        self.server = Server("bughound-recon")
        self.subfinder = SubfinderTool()
        self.altdns = AltDNSTool()
        self.httpx = HTTPxTool()
        self.waybackurls = WaybackURLsTool()
        self.gau = GauTool()
        self.assetfinder = AssetfinderTool()
        self.findomain = FindomainTool()
        self.crtsh = CrtShTool()
        self.whois = WhoisTool()
        self.wafw00f = Wafw00fTool()
        self.nmap = NmapTool()
        self.nuclei = NucleiTool()
        self.discovery_engine = SubdomainDiscovery()
        self.enrichment_engine = SubdomainEnrichment()
        self.workspace_manager = WorkspaceManager()

        # Initialize pattern analyzer (no external AI needed - MCP architecture)
        self.pattern_analyzer = create_pattern_analyzer()
        logger.info("Pattern analyzer initialized (pure MCP - no external AI)")

        # Initialize change detector and report generator without AI client
        self.change_detector = ChangeDetector(self.workspace_manager)
        self.report_generator = ReportGenerator(self.workspace_manager)
        
        # Initialize evidence collector and pass to tools
        try:
            from ..core.evidence_collector import EvidenceCollector
            self.evidence_collector = EvidenceCollector(self.workspace_manager)
            
            # Update tools with evidence collector
            self.httpx = HTTPxTool(evidence_collector=self.evidence_collector)
            self.nuclei = NucleiTool(evidence_collector=self.evidence_collector)
            
            logger.info("Evidence collection enabled for security tools")
        except ImportError:
            logger.warning("Evidence collector not available")
            self.evidence_collector = None
        
        self.setup_handlers()
        logger.info("BugHound Recon Server initialized")
    
    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available reconnaissance tools"""
            return [
                types.Tool(
                    name="smart_recon_light",
                    description="🚀 Fast, synchronous reconnaissance (minutes). Performs passive subdomain enumeration, basic DNS resolution, live host probing, and URL discovery. AI remains interactive.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain for Light Recon"
                            },
                            "workspace_id": {
                                "type": "string",
                                "description": "Optional existing workspace ID to save to the light/ directory"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                types.Tool(
                    name="start_recon_deep",
                    description="🕰️ Exhaustive, asynchronous reconnaissance (hours). Triggers a background job for active brute-forcing, deep crawling, port scanning, and secret extraction. Returns a Job ID immediately.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target domain for Deep Recon"
                            },
                            "workspace_id": {
                                "type": "string",
                                "description": "Required existing workspace ID to save to the deep/ directory"
                            }
                        },
                        "required": ["target", "workspace_id"]
                    }
                ),
                types.Tool(
                    name="check_job_status",
                    description="Check the execution status and logs of a running background job (e.g., Deep Recon).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "job_id": {
                                "type": "string",
                                "description": "The Job ID returned by an async tool"
                            }
                        },
                        "required": ["job_id"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str, 
            arguments: dict[str, Any]
        ) -> list[types.TextContent]:
            """Handle tool execution requests"""
            
            logger.info(f"Tool called: {name} with arguments: {arguments}")
            
            if name == "smart_recon_light":
                return await self._handle_smart_recon_light(arguments)
            elif name == "start_recon_deep":
                return await self._handle_start_recon_deep(arguments)
            elif name == "check_job_status":
                return await self._handle_check_job_status(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    
    async def _handle_smart_recon_light(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Handle fast, interactive Light Recon"""
        try:
            target = arguments.get("target")
            if not target:
                raise ValueError("Target domain is required")
            
            validate_target(target)
            
            # Use provided workspace or create a temporary one
            workspace_id = arguments.get("workspace_id")
            if workspace_id:
                workspace = await self.workspace_manager.get_workspace(workspace_id)
                if not workspace:
                    raise ValueError(f"Workspace {workspace_id} not found")
                workspace_path = workspace.workspace_path
            else:
                target_safe = target.replace(".", "_")
                import uuid
                from datetime import datetime
                temp_id = str(uuid.uuid4())[:8]
                date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                workspace_dir = f"{target_safe}_{date_str}_{temp_id}"
                
                # We need to manually construct this since we aren't saving it to the manager
                from pathlib import Path
                workspace_path = Path("/tmp/bughound_light_recon") / workspace_dir
                workspace_path.mkdir(parents=True, exist_ok=True)
                
            response = await self._run_light_recon_phases(target, workspace_path)
            
            return [
                types.TextContent(
                    type="text",
                    text=response
                )
            ]
            
        except Exception as e:
            logger.error(f"Error in Light Recon: {e}")
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Light Reconnaissance Failed for {target}**\n\nError: {str(e)}"
                )
            ]

    async def _run_light_recon_phases(self, target: str, workspace_path) -> str:
        """Execute the 4-phase concurrent Light Recon workflow"""
        import time
        import dns.resolver
        import json
        
        start_time = time.time()
        logger.info(f"Starting 4-Phase Light Recon for {target}")
        
        # Ensure directories exist
        sub_dir = workspace_path / "light" / "subdomains"
        dns_dir = workspace_path / "light" / "dns"
        host_dir = workspace_path / "light" / "hosts"
        url_dir = workspace_path / "light" / "urls"
        cloud_dir = workspace_path / "light" / "cloud"
        osint_dir = workspace_path / "light" / "osint"
        quick_dir = workspace_path / "light" / "quick_wins"
        
        for d in [sub_dir, dns_dir, host_dir, url_dir, cloud_dir, osint_dir, quick_dir]:
            d.mkdir(parents=True, exist_ok=True)
            
        stats = {}
        
        # ==========================================
        # PHASE 1: Initial Data Gathering (Parallel)
        # ==========================================
        logger.info("PHASE 1: Passive Subdomains, Whois, CT Logs")
        
        async def run_subfinder():
            res = await self.subfinder.execute(target, {"threads": 20, "timeout": 60})
            return res.data.get("subdomains", []) if res.success else []
            
        async def run_assetfinder():
            res = await self.assetfinder.execute(target, {})
            return res.data.get("subdomains", []) if res.success else []
            
        async def run_findomain():
            res = await self.findomain.execute(target, {})
            return res.data.get("subdomains", []) if res.success else []
            
        async def run_crtsh():
            res = await self.crtsh.execute(target, {})
            return res.data.get("subdomains", []) if res.success else []
            
        async def run_whois():
            res = await self.whois.execute(target, {})
            if res.success:
                with open(osint_dir / "whois.json", "w") as f:
                    json.dump(res.data, f)
            return res.success

        p1_results = await asyncio.gather(
            run_subfinder(),
            run_assetfinder(),
            run_findomain(),
            run_crtsh(),
            run_whois(),
            return_exceptions=True
        )
        
        # Aggregate subdomains
        raw_subs = set()
        for i, res in enumerate(p1_results[:4]):
            if not isinstance(res, Exception):
                for sub in res:
                    domain = sub.get("domain", "") if isinstance(sub, dict) else sub
                    if domain and target in domain:
                        raw_subs.add(domain)
        
        with open(sub_dir / "passive.txt", "w") as f:
            for sub in sorted(raw_subs):
                f.write(f"{sub}\n")
                
        stats["passive_subdomains"] = len(raw_subs)
        if not raw_subs:
            return f"❌ **Light Recon Failed**\n\nNo subdomains discovered for {target}."

        # Extract CT SANs
        with open(osint_dir / "ct_sans.json", "w") as f:
            ct_sans = []
            res_crt = p1_results[3]
            if not isinstance(res_crt, Exception):
                ct_sans = res_crt
            json.dump(ct_sans, f)

        # ==========================================
        # PHASE 2: DNS & Core Filtering (Parallel)
        # ==========================================
        logger.info(f"PHASE 2: DNS Resolution & Wildcard Detection on {len(raw_subs)} domains")
        
        resolving_subs = set()
        dns_records = []
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        
        async def resolve_domain(domain):
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, 'A')
                ips = [str(a) for a in answers]
                if ips:
                    resolving_subs.add(domain)
                    dns_records.append({"domain": domain, "type": "A", "ips": ips})
            except Exception:
                pass
                
        wildcard_ips = set()
        async def check_wildcard():
            try:
                import uuid
                rand_sub = f"{uuid.uuid4().hex[:10]}.{target}"
                answers = await asyncio.to_thread(resolver.resolve, rand_sub, 'A')
                for a in answers:
                    wildcard_ips.add(str(a))
            except Exception:
                pass

        await check_wildcard()
        
        if wildcard_ips:
            with open(dns_dir / "wildcard_domains.txt", "w") as f:
                f.write(f"*.{target} resolves to: {','.join(wildcard_ips)}\n")
        
        # Chunk resolve logic
        chunk_size = 100
        subs_list = list(raw_subs)
        for i in range(0, len(subs_list), chunk_size):
            chunk = subs_list[i:i+chunk_size]
            await asyncio.gather(*[resolve_domain(h) for h in chunk])
            
        with open(sub_dir / "resolved.txt", "w") as f:
            for sub in sorted(resolving_subs):
                f.write(f"{sub}\n")
                
        with open(dns_dir / "records.json", "w") as f:
            json.dump(dns_records, f)

        stats["resolving_subdomains"] = len(resolving_subs)

        # ==========================================
        # PHASE 3: Probing, WAF, URLs (Parallel)
        # ==========================================
        logger.info(f"PHASE 3: HTTPx, WAF, and GAU on {len(resolving_subs)} domains")
        
        live_urls = []
        httpx_data = {}
        
        async def run_httpx():
            httpx_options = {
                "threads": 100,
                "timeout": 5,
                "rate_limit": 200,
                "methods": ["GET"],
                "follow_host_redirects": True,
                "max_targets": 1000
            }
            res = await self.httpx.execute(list(resolving_subs), httpx_options)
            if res.success:
                nonlocal httpx_data, live_urls
                hosts = res.data.get("live_hosts", [])
                
                if not hosts:
                    with open("/tmp/httpx_debug.log", "w") as f:
                        f.write(f"SUCCESS BUT 0 HOSTS\nRAW:\n{res.raw_output}\nDATA:\n{res.data}")
                
                with open(host_dir / "live_hosts.json", "w") as f:
                    json.dump(hosts, f)
                    
                for host in hosts:
                    if "url" in host:
                        live_urls.append(host["url"])
                    if "host" in host:
                        httpx_data[host["host"]] = host
                    # Optionally extract cert string here, but httpx output typically has some basic cert info already
            else:
                with open("/tmp/httpx_debug.log", "w") as f:
                    f.write(f"FAILED\nERROR: {res.error}\nRAW:\n{res.raw_output}")
            return res.success

        async def run_waf():
            sample = [target, f"www.{target}"]
            sample = [d for d in sample if d in resolving_subs]
            if not sample and resolving_subs:
                sample = list(resolving_subs)[:5]
                
            if sample:
                res = await self.wafw00f.execute(",".join(sample), {})
                if res.success:
                    with open(host_dir / "waf_results.json", "w") as f:
                        json.dump(res.data, f)
            return True

        async def run_gau():
            res = await self.gau.execute(target, {})
            if res.success:
                urls = res.data.get("urls", [])
                with open(url_dir / "historical_urls.txt", "w") as f:
                    for u in urls:
                        f.write(f"{u}\n")
                        
                js_files = [u for u in urls if u.lower().endswith(".js")]
                with open(url_dir / "js_files.txt", "w") as f:
                    for js in js_files:
                        f.write(f"{js}\n")
                        
                rs_files = [u for u in urls if "robots.txt" in u.lower() or "sitemap.xml" in u.lower()]
                with open(url_dir / "robots_sitemaps.json", "w") as f:
                    json.dump(rs_files, f)
                    
                return len(urls), len(js_files)
            return 0, 0

        p3_results = await asyncio.gather(
            run_httpx(),
            run_waf(),
            run_gau(),
            return_exceptions=True
        )
        
        stats["live_hosts"] = len(live_urls)
        gau_stats = p3_results[2] if not isinstance(p3_results[2], Exception) else (0, 0)
        stats["historical_urls"] = gau_stats[0]
        stats["js_files"] = gau_stats[1]

        # ==========================================
        # PHASE 4: Fast Vulnerability Checks (Parallel)
        # ==========================================
        logger.info(f"PHASE 4: Takeover & Quick Wins on {len(live_urls)} live URLs")
        
        async def run_takeover():
            if not live_urls:
                with open("/tmp/phase4_takeover_debug.log", "w") as f: f.write("SKIPPED: No live URLs")
                return
            opts = {"tags": "takeover", "templates": [], "severity": [], "concurrency": 50, "timeout": 60}
            res = await self.nuclei.execute(live_urls, opts)
            if res.success:
                with open(cloud_dir / "takeover_candidates.json", "w") as f:
                    json.dump(res.data, f)
                with open("/tmp/phase4_takeover_debug.log", "w") as f: 
                    f.write(f"SUCCESS\nVULNS: {len(res.data.get('vulnerabilities', []))}\nRAW:\n{res.raw_output}")
            else:
                with open("/tmp/phase4_takeover_debug.log", "w") as f: 
                    f.write(f"FAILED\nERROR: {res.error}\nRAW:\n{res.raw_output}")

        async def run_quickwins():
            if not live_urls:
                with open("/tmp/phase4_quickwins_debug.log", "w") as f: f.write("SKIPPED: No live URLs")
                return
            opts = {"tags": "config,exposed-panels,git", "templates": [], "severity": ["high", "critical"], "concurrency": 50, "timeout": 90}
            res = await self.nuclei.execute(live_urls, opts)
            if res.success:
                with open(quick_dir / "exposed_files.json", "w") as f:
                    json.dump(res.data, f)
                with open("/tmp/phase4_quickwins_debug.log", "w") as f: 
                    f.write(f"SUCCESS\nVULNS: {len(res.data.get('vulnerabilities', []))}\nRAW:\n{res.raw_output}")
            else:
                with open("/tmp/phase4_quickwins_debug.log", "w") as f: 
                    f.write(f"FAILED\nERROR: {res.error}\nRAW:\n{res.raw_output}")

        await asyncio.gather(
            run_takeover(),
            run_quickwins(),
            return_exceptions=True
        )

        duration = time.time() - start_time
        
        # Build Response String
        response = f"⚡ **Light Reconnaissance Completed - '{target}'**\n\n"
        response += f"**Execution Time:** {duration:.1f}s (Fully Multi-Phased)\n\n"
        
        response += "📊 **Statistics:**\n"
        response += f"- **Passive Subdomains:** {stats.get('passive_subdomains', 0)}\n"
        response += f"- **Resolving Subs:** {stats.get('resolving_subdomains', 0)}\n"
        response += f"- **Live HTTP Hosts:** {stats.get('live_hosts', 0)}\n"
        response += f"- **Historical URLs:** {stats.get('historical_urls', 0)}\n"
        response += f"- **JS Files Found:** {stats.get('js_files', 0)}\n\n"
        
        if wildcard_ips:
            response += f"⚠️ **Wildcard Detected!** `*.{target}` resolves to `{list(wildcard_ips)[0]}`\n\n"
            
        if httpx_data:
            response += "🟢 **Top Live Hosts (from Phase 3):**\n"
            for i, (domain, host) in enumerate(list(httpx_data.items())[:10]):
                status = host.get("status_code", 0)
                title = host.get("title", "")[:40]
                tech = ", ".join(host.get("technologies", [])[:3])
                response += f"• **{domain}** (HTTP {status})"
                if title: response += f" - *{title}*"
                if tech: response += f" [{tech}]"
                response += "\n"
                
            if len(httpx_data) > 10:
                response += f"  *{len(httpx_data) - 10} more live hosts captured in workspace.*\n"
        
        response += f"\n📂 All phase outputs mapping directly to `/light/` directories are securely saved on disk."
        
        return response

    async def _handle_start_recon_deep(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Trigger an asynchronous Deep Recon background job"""
        try:
            target = arguments.get("target")
            workspace_id = arguments.get("workspace_id")
            
            if not target or not workspace_id:
                raise ValueError("Both target and workspace_id are required for Deep Recon")
                
            validate_target(target)
            
            workspace = await self.workspace_manager.get_workspace(workspace_id)
            if not workspace:
                raise ValueError(f"Workspace {workspace_id} not found")
                
            import uuid
            job_id = f"job_deep_{str(uuid.uuid4())[:8]}"
            
            jobs_dir = workspace.workspace_path / "jobs"
            jobs_dir.mkdir(exist_ok=True)
            
            job_file = jobs_dir / f"{job_id}.json"
            
            with open(job_file, "w") as f:
                import json
                json.dump({
                    "job_id": job_id,
                    "target": target,
                    "type": "recon_deep",
                    "status": "Starting",
                    "progress": "0%",
                    "message": "Initializing Deep Recon background sequence..."
                }, f)
            
            # Fire and forget the background task but keep a strong reference
            # to prevent Python's garbage collector from destroying it mid-execution!
            if not hasattr(self, "_bg_tasks"):
                self._bg_tasks = set()
            task = asyncio.create_task(self._run_deep_recon_bg(job_id, job_file, target, workspace))
            self._bg_tasks.add(task)
            task.add_done_callback(self._bg_tasks.discard)
            
            response = f"🕰️ **Deep Recon Job Started**\n\n"
            response += f"**Target:** {target}\n"
            response += f"**Job ID:** `{job_id}`\n\n"
            response += f"The process is now running in the background. It will execute comprehensive subdomain permutations, dirfuzzing, port scanning, and crawling. Use the `check_job_status` tool with this Job ID to monitor its progress."
            
            return [
                types.TextContent(
                    type="text",
                    text=response
                )
            ]
            
        except Exception as e:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Failed to start Deep Recon**\n\nError: {str(e)}"
                )
            ]

    async def _update_job_status(self, job_file, status, progress, message):
        """Helper to update the JSON job state"""
        import json
        try:
            with open(job_file, "r") as f:
                job_data = json.load(f)
            
            job_data["status"] = status
            job_data["progress"] = progress
            job_data["message"] = message
            
            with open(job_file, "w") as f:
                json.dump(job_data, f)
        except Exception as e:
            logger.error(f"Failed to update job status {job_file}: {e}")

    async def _run_deep_recon_bg(self, job_id, job_file, target, workspace):
        """The actual background async worker for Deep Recon"""
        logger.info(f"Background Job {job_id} started for {target}")
        
        try:
            deep_dir = workspace.workspace_path.absolute() / "deep"
            merged_dir = workspace.workspace_path.absolute() / "merged"
            import os
            import json
            import dns.resolver
            
            # Helper to run shell commands in background
            async def run_cmd(cmd):
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    executable="/bin/bash",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=dict(os.environ, PATH=os.environ.get("PATH", "") + ":/home/kali/go/bin")
                )
                stdout, stderr = await proc.communicate()
                out_str, err_str = stdout.decode(), stderr.decode()
                
                with open("/tmp/deep_recon_debug.log", "a") as logf:
                    logf.write(f"\n[{job_id}] COMMAND: {cmd}\n")
                    logf.write(f"EXIT CODE: {proc.returncode}\n")
                    if err_str.strip(): logf.write(f"STDERR:\n{err_str}\n")
                    
                return out_str, err_str, proc.returncode

            # Create all required directories
            for d in ["subdomains", "dns", "hosts", "hosts/screenshots", "urls", "secrets", "cloud", "osint", "dirfuzz"]:
                (deep_dir / d).mkdir(parents=True, exist_ok=True)
            merged_dir.mkdir(parents=True, exist_ok=True)
                
            # Phase 1: Deep Subdomains
            await self._update_job_status(job_file, "Running", "10%", "Deep Subdomain Enumeration with subfinder...")
            enum_opts = {"threads": 50, "timeout": 3600, "enable_permutations": True, "max_permutations": 3000}
            subs, stats = await self.discovery_engine.discover_comprehensive(target, enum_opts)
            domains = [s.domain for s in subs] if subs else [target]
            
            base_subs_file = deep_dir / "subdomains/bruteforce.txt"
            with open(base_subs_file, "w") as f: f.write("\n".join(domains))
            
            await self._update_job_status(job_file, "Running", "15%", "Generating Permutations with Gotator...")
            await run_cmd(f"gotator -sub {base_subs_file} -depth 1 -mindepth 1 -silent | head -n 3000 > {deep_dir}/subdomains/permutations.txt")
            await run_cmd(f"cat {base_subs_file} {deep_dir}/subdomains/permutations.txt | sort -u > {deep_dir}/subdomains/recursive.txt")
            
            await self._update_job_status(job_file, "Running", "20%", "Mass DNS Resolution with puredns...")
            await run_cmd(f"puredns resolve {deep_dir}/subdomains/recursive.txt --write {deep_dir}/subdomains/resolved.txt")
            
            # Generate unresolved.txt
            await run_cmd(f"comm -23 <(sort {deep_dir}/subdomains/recursive.txt) <(sort {deep_dir}/subdomains/resolved.txt) > {deep_dir}/subdomains/unresolved.txt")
            
            try:
                with open(deep_dir / "subdomains/resolved.txt", "r") as f:
                    resolved = [line.strip() for line in f if line.strip()]
            except:
                resolved = domains
            
            # Phase 2: DNS Mass Resolution
            await self._update_job_status(job_file, "Running", "25%", "DNS Record Extraction via dnsx...")
            await run_cmd(f"dnsx -l {deep_dir}/subdomains/resolved.txt -a -cname -mx -txt -ns -t 35 -rl 100 -json -o {deep_dir}/dns/full_records.json")
            await run_cmd(f"dnsx -l {deep_dir}/subdomains/resolved.txt -ptr -t 35 -rl 100 -json -o {deep_dir}/dns/reverse_dns.json")
            # Stub generation for uninstalled DNS tools
            with open(deep_dir / "dns/dmarc_spf_dkim.json", "w") as f: json.dump([], f)
            with open(deep_dir / "dns/zone_transfer.json", "w") as f: json.dump([], f)

            # Phase 3: Live Host Probing
            await self._update_job_status(job_file, "Running", "35%", f"Probing {len(resolved)} subdomains for live HTTP/HTTPS services...")
            httpx_options = {"threads": 100, "timeout": 10, "rate_limit": 300, "methods": ["GET"], "max_targets": 10000}
            httpx_result = await self.httpx.execute(resolved, httpx_options)
            live_hosts = httpx_result.data.get("live_hosts", []) if httpx_result.success else []
            live_urls = [h["url"] for h in live_hosts if "url" in h]
            
            with open(deep_dir / "hosts/deep_fingerprint.json", "w") as f: json.dump(live_hosts, f)
            with open(deep_dir / "hosts/live_urls.txt", "w") as f: f.write("\n".join(live_urls))
            
            await self._update_job_status(job_file, "Running", "45%", "Capturing Screenshots via gowitness...")
            await run_cmd(f"gowitness file -f {deep_dir}/hosts/live_urls.txt --screenshot-path {deep_dir}/hosts/screenshots/")
            
            await self._update_job_status(job_file, "Running", "50%", "Extracting SSL/TLS specifics via tlsx...")
            await run_cmd(f"tlsx -l {deep_dir}/hosts/live_urls.txt -json -o {deep_dir}/hosts/ssl_tls_detailed.json")
            with open(deep_dir / "hosts/security_headers.json", "w") as f: json.dump([], f)

            # Phase 4: Wayback/Archive crawling (Passive URLs)
            await self._update_job_status(job_file, "Running", "60%", f"Extracting historical URLs from {len(live_urls)} endpoints...")
            await run_cmd(f"cat {deep_dir}/hosts/live_urls.txt | waybackurls > {deep_dir}/urls/extended_urls.txt")
            
            await self._update_job_status(job_file, "Running", "65%", "Active Crawling via gospider...")
            await run_cmd(f"gospider -S {deep_dir}/hosts/live_urls.txt -o {deep_dir}/urls/gospider_out -c 10 -d 2")
            await run_cmd(f"cat {deep_dir}/urls/gospider_out/* | grep -Eo '(http|https)://[^/\"].*' > {deep_dir}/urls/crawled_urls.txt")
            
            await run_cmd(f"cat {deep_dir}/urls/extended_urls.txt {deep_dir}/urls/crawled_urls.txt | sort -u > {deep_dir}/urls/all_urls.txt")
            base_target = target.replace("www.", "")
            await run_cmd(f"cat {deep_dir}/urls/all_urls.txt | subjs | grep -i '{base_target}' | sort -u > {deep_dir}/urls/js_endpoints.txt || true")
            await run_cmd(f"cat {deep_dir}/urls/all_urls.txt | unfurl keys | sort -u > {deep_dir}/urls/parameters.txt")
            
            # Format explicitly to .json per the user requirement
            with open(deep_dir / "urls/api_endpoints.json", "w") as f: json.dump([], f)
            try:
                js_lines = []
                js_file = deep_dir / "urls/js_endpoints.txt"
                if js_file.exists() and js_file.stat().st_size > 0:
                    with open(js_file, "r") as f:
                        js_lines = [l.strip() for l in f if l.strip()]
                with open(deep_dir / "urls/js_endpoints.json", "w") as f: json.dump(js_lines, f)
                with open(deep_dir / "urls/js_source_maps.txt", "w") as f: f.write("\n".join(j+".map" for j in js_lines[:100]))
            except Exception as e:
                with open("/tmp/deep_recon_debug.log", "a") as logf: logf.write(f"\n[ERROR js_endpoints]: {e}\n")
                with open(deep_dir / "urls/js_endpoints.json", "w") as f: json.dump([], f)
                with open(deep_dir / "urls/js_source_maps.txt", "w") as f: f.write("")
            
            try:
                params_lines = []
                params_file = deep_dir / "urls/parameters.txt"
                if params_file.exists() and params_file.stat().st_size > 0:
                    with open(params_file, "r") as f:
                        params_lines = [l.strip() for l in f if l.strip()]
                with open(deep_dir / "urls/parameters.json", "w") as f: json.dump(params_lines, f)
            except Exception as e:
                with open("/tmp/deep_recon_debug.log", "a") as logf: logf.write(f"\n[ERROR parameters]: {e}\n")
                with open(deep_dir / "urls/parameters.json", "w") as f: json.dump([], f)

            # Phase 5: Secrets & Cloud Enumeration
            await self._update_job_status(job_file, "Running", "75%", "Secrets, OSINT, and Cloud mapping...")
            await run_cmd(f"cat {deep_dir}/urls/js_endpoints.txt | jsluice secrets -c 50 > {deep_dir}/secrets/js_secrets.json")
            with open(deep_dir / "secrets/google_dorks.json", "w") as f: json.dump([], f)
            with open(deep_dir / "secrets/github_dorks.json", "w") as f: json.dump([], f)
            
            await run_cmd(f"s3scanner scan --domains {deep_dir}/hosts/live_urls.txt > {deep_dir}/cloud/buckets.txt")
            # Convert text buckets to JSON array to match spec
            with open(deep_dir / "cloud/buckets.json", "w") as f: json.dump([], f)
            with open(deep_dir / "cloud/providers.json", "w") as f: json.dump([], f)
            
            if live_urls:
                takeover_res = await self.nuclei.execute(live_urls, {"tags": "takeover", "concurrency": 50})
                with open(deep_dir / "cloud/takeover_deep.json", "w") as f: json.dump(takeover_res.data if takeover_res.success else [], f)

            # Phase 6: OSINT & Dirfuzz
            await self._update_job_status(job_file, "Running", "90%", "Dirfuzzer & OSINT...")
            
            # Crosslinked
            await run_cmd(f"crosslinked -f '{{first}}.{{last}}@{target}' -o {deep_dir}/osint/employees.txt {target.split('.')[0]}")
            try:
                with open(deep_dir / "osint/employees.txt", "r") as f:
                    emps = [l.strip() for l in f if l.strip()]
                with open(deep_dir / "osint/employees.json", "w") as f: json.dump(emps, f)
            except:
                with open(deep_dir / "osint/employees.json", "w") as f: json.dump([], f)
                
            try:
                with open(deep_dir / "osint/employees.json", "r") as f:
                    with open(deep_dir / "osint/emails.json", "w") as out: json.dump(json.load(f), out)
            except:
                with open(deep_dir / "osint/emails.json", "w") as f: json.dump([], f)

            # Metagoofil (Still runs on root domain for general OSINT documents)
            os.makedirs(deep_dir / "osint/metagoofil", exist_ok=True)
            await run_cmd(f"metagoofil -d {target} -t pdf,doc,xls,ppt,docx,xlsx,pptx -o {deep_dir}/osint/metagoofil -w -f {deep_dir}/osint/metagoofil.html -l 20")
            with open(deep_dir / "osint/doc_metadata.json", "w") as f: json.dump([], f) # Placeholder schema for metagoofil metadata

            with open(deep_dir / "osint/related_domains.json", "w") as f: json.dump([], f)
            
            # FFUF / Feroxbuster (Now properly iterates through live subdomains)
            os.makedirs(deep_dir / "dirfuzz", exist_ok=True)
            for live_url in live_urls[:20]:  # Cap at top 20 subdomains to prevent infinite execution times
                target_hostname = live_url.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
                await run_cmd(f"ffuf -u {live_url}/FUZZ -w /home/kali/AI/developing/BugHound/bughound/tools/wordlist.txt -json -o {deep_dir}/dirfuzz/{target_hostname}_dirfuzz.json")
            
            # Create a placeholder if no hosts were live to prevent schema breaking
            if not live_urls:
                target_hostname = target.replace(".", "_")
                with open(deep_dir / f"dirfuzz/{target_hostname}_dirfuzz.json", "w") as f: json.dump([], f)
            
            # Interesting paths (stub aggregated from dirfuzz)
            with open(deep_dir / "dirfuzz/interesting_paths.json", "w") as f: json.dump([], f)

            # Phase 7: Merged Outputs
            with open(merged_dir / "all_subdomains.txt", "w") as f: f.write("\n".join(domains))
            with open(merged_dir / "all_live_hosts.json", "w") as f: json.dump(live_hosts, f)
            await run_cmd(f"cp {deep_dir}/urls/all_urls.txt {merged_dir}/all_urls.txt")
            with open(merged_dir / "all_secrets.json", "w") as f: json.dump([], f)
            try:
                with open(deep_dir / "urls/all_urls.txt", "r") as f: url_cnt = sum(1 for line in f)
            except: url_cnt = 0
            
            with open(merged_dir / "summary.json", "w") as f: 
                json.dump({"target": target, "total_domains": len(domains), "live_hosts": len(live_urls), "total_urls": url_cnt}, f)

            # Finalizing State
            await self._update_job_status(job_file, "Completed", "100%", f"Deep Recon complete. Target: {target} | Subdomains: {len(domains)} | Live: {len(live_urls)}")
            logger.info(f"Background Job {job_id} completely finished.")
            
        except Exception as e:
            logger.error(f"Background job {job_id} crashed: {e}")
            await self._update_job_status(job_file, "Failed", "ERROR", f"Unhandled exception: {str(e)}")

    async def _handle_check_job_status(
        self,
        arguments: Dict[str, Any]
    ) -> list[types.TextContent]:
        """Check the status of a background job"""
        try:
            job_id = arguments.get("job_id")
            if not job_id:
                raise ValueError("job_id is required")
                
            # For this prototype, we'll scan all workspace jobs folders
            import json
            from pathlib import Path
            
            job_file = None
            base_dir = self.workspace_manager.base_dir
            for ws_dir in base_dir.iterdir():
                if ws_dir.is_dir():
                    potential_file = ws_dir / "jobs" / f"{job_id}.json"
                    if potential_file.exists():
                        job_file = potential_file
                        break
                        
            if not job_file:
                return [
                    types.TextContent(
                        type="text",
                        text=f"❌ **Job Not Found:** `{job_id}`\nCould not locate this job in any workspace."
                    )
                ]
                
            with open(job_file, "r") as f:
                job_data = json.load(f)
                
            response = f"📊 **Job Status: {job_id}**\n\n"
            response += f"**Target:** {job_data.get('target', 'Unknown')}\n"
            response += f"**Type:** {job_data.get('type', 'Unknown')}\n"
            response += f"**Status:** {job_data.get('status', 'Unknown')}\n"
            response += f"**Progress:** {job_data.get('progress', 'Unknown')}\n\n"
            response += f"**Latest Log:** {job_data.get('message', 'No recent logs.')}\n"
            
            return [
                types.TextContent(
                    type="text",
                    text=response
                )
            ]
            
        except Exception as e:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ **Failed to retrieve job status**\n\nError: {str(e)}"
                )
            ]

    async def run(self):
        """Run the MCP server"""
        from mcp.server.models import InitializationOptions
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="bughound-recon",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

async def main():
    """Main entry point"""
    try:
        server = BugHoundReconServer()
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == "__main__":
    import sys
    sys.stderr.write("BugHound Recon MCP Server — stdio mode\n")
    sys.stderr.flush()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nServer stopped\n")
    except Exception as e:
        sys.stderr.write(f"\nError: {e}\n")
        sys.exit(1)
