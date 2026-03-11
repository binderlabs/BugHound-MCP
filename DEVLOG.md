# BugHound Development Log

## 2026-03-11 - Day 0: Architecture Planning

### Decisions Made
- Moving from 5 MCP servers to 1 single server with namespaced tools
- 7-stage pipeline: Init, Enumerate, Discover, Analyze, Test, Validate, Report
- Stages collapse based on target type (single host skips enumeration, etc.)
- Depth (light/deep) and scope (target type) are independent axes
- NO internal AI calls in MCP server. AI reasoning happens at client layer.
- Workspace uses data-type-based folders, NOT light/deep split
- Lazy directory creation (only when data is written)
- All tool wrappers use unified tool_runner
- All stored JSON validated with Pydantic
- Target: Black Hat Arsenal demo, April 2026

### Existing Codebase Assessment
- 29K lines of Python across 85 files
- ~10K lines actually usable (tool wrappers, light recon pipeline, workspace CRUD)
- 5 MCP servers exist (1 working, 1 broken, 3 stubs)
- 22 tool wrappers (13 recon + 8 scanning + 1 discovery)
- 4 critical bugs, 3 security issues, hardcoded API key
- Key code to KEEP: tool wrappers, light recon pipeline, workspace CRUD, job pattern, report templates
- Key code to DELETE: commander, workflow engine, AI analyzer/client, prioritization engine
- Key code to REWRITE: analyze server, decision engine, workspace structure, deep recon

### What's Next
- Phase 0 Day 1: cleanup dead code, create new project skeleton
- Phase 0 Day 2: build core infrastructure (tool_runner, job_manager, workspace)

---

## 2026-03-11 - Day 1: Cleanup + Skeleton

### What Was Done
- Removed hardcoded OpenRouter API key from config.py (security fix)
- Deleted 9 dead code files: commander_server, workflow_engine, ai_analyzer, ai_client, prioritization_engine, prompts/recon_analysis, scan_modes, recon_server.py.bak, bughound/-
- Deleted 5 dead directories: backups/ (13MB), docs/legacy_plans/ (30+ files), bughound/scripts/ (14 test harnesses), duplicate config/ at root, old workspaces
- Archived change_detector.py + evidence_collector.py to _archive/
- Fixed setup.py entry_points referencing non-existent scan_server
- Removed unused anthropic + openai from dependencies
- Deleted bughound/test_results/, tests/legacy_tests/, demo/
- Created new project skeleton: server.py, core/, stages/, schemas/, utils/
- Initialized git repo, first commit

### Results
- 410 files -> 110 files (-300)
- 39,275 Python LOC -> 17,565 LOC (-21,710)

---

## 2026-03-11 - Day 2: Core Infrastructure

### What Was Built

**1. bughound/config/settings.py** (38 lines)
- Single source of truth for all configuration
- TOOL_PATHS, DEFAULT_TIMEOUT, WORKSPACE_BASE_DIR, MAX_CONCURRENT_JOBS, JOB_TIMEOUT
- All configurable via environment variables
- Deleted old bughound/config.py (shadowed config/ package)

**2. bughound/core/tool_runner.py** (326 lines)
- Binary discovery: shutil.which() + configurable TOOL_PATHS
- is_available() pre-flight check
- Input sanitization: domain, URL, IP validation + shell metacharacter rejection
- Async execution via create_subprocess_exec (never shell=True)
- Configurable timeout with partial result collection
- Structured ToolResult return on success/failure/timeout/not-found
- Install hints for 18 known tools

**3. bughound/core/job_manager.py** (405 lines)
- Full job lifecycle: create, start, update_progress, complete, fail, cancel
- O(1) status lookup via in-memory index (not linear workspace scan)
- Timeout watchdog pattern for automatic job cancellation
- Terminal state protection (fail_job won't overwrite CANCELLED/TIMED_OUT)
- Lazy init: rebuilds index from disk on first use (server restart safe)
- Configurable max concurrent jobs limit (default 5)
- Cleanup of old completed/failed jobs

**4. bughound/core/workspace.py** (310 lines)
- Workspace CRUD: create, get, list, delete
- Lazy directory creation (only when data is written)
- Pydantic-validated JSON writes via DataWrapper envelope
- Text file writes: sorted, deduplicated
- Append with merge+dedup (text union, JSON dedup by key)
- Metadata management: update_metadata, add_stage_history, update_stats
- Scope checking with wildcard support (fnmatch)
- Auto-scope generation from target

**5. bughound/schemas/models.py** (193 lines)
- ToolResult, ToolError, ToolErrorType
- JobRecord, JobStatus
- WorkspaceMetadata, WorkspaceConfig, WorkspaceSummary, WorkspaceState
- ScopeConfig, TimeoutConfig, StageEntry, WorkspaceStats
- DataWrapper (standard JSON envelope)
- TargetType enum

### Design Decisions
- tool_runner.run() never raises — always returns ToolResult
- Job watchdog as separate asyncio task instead of wait_for wrapper
- Workspace write_data auto-detects format from file extension (.txt vs .json)
- Scope auto-generated from target at workspace creation time

### What's Next
- Phase 1 Day 3: target_classifier.py + register MCP tools in server.py

---

## 2026-03-11/12 - Days 5-6: Stage 2 (Discover)

### What Was Built

**Day 5 — Phase 2A: Probing + Fingerprinting**

- Rewrote httpx.py (511 → 99 lines): uses tool_runner.run(), temp file for batch targets, JSONL parsing with full fingerprint capture (url, host, status, title, tech, cdn, web_server, etc.)
- Rewrote wafw00f.py (47 → 65 lines): uses tool_runner.run(), JSON array extraction from mixed output
- Built stages/discover.py Phase 2A: httpx probe → WAF detection → intelligence flag generation
- 6 intelligence flags: NO_WAF, NON_CDN_IP, DEFAULT_PAGE, GRAPHQL, OLD_TECH, DEBUG_MODE
- OLD_TECH matches 10 patterns (WordPress <6, jQuery <3.5, PHP 5.x, Apache 2.2, etc.)
- bughound_discover MCP tool: sync for single hosts, async job for broad domains
- Tested on scanme.nmap.org: Apache 2.4.7 + Ubuntu detected in 6.35s

**Day 6 — Phase 2B-2D: URLs, JS, Secrets, Parameters**

- Rewrote gau.py (49 → 38 lines): tool_runner pattern, deduped URL output
- Rewrote waybackurls.py (490 → 36 lines): tool_runner pattern
- Created gospider.py (66 lines): new wrapper, JSONL parsing, depth-configurable crawler
- Created js_analyzer.py (205 lines): pure Python, no binary needed
  - 10 secret patterns (AWS keys, API keys, tokens, private keys, JWTs, etc.)
  - 5 endpoint extraction patterns (fetch, axios, API paths, internal routes)
  - Concurrent download with semaphore (max 20 parallel), 5MB size cap
- Extended discover.py with Phases 2B-2D:
  - 2B: gau + waybackurls in parallel + gospider crawl → urls/crawled.json
  - 2C: JS analysis → secrets/js_secrets.json + endpoints/api_endpoints.json + endpoints/hidden_endpoints.json
  - 2D: Parameter extraction from all URLs → urls/parameters.json
- Progress callbacks for async jobs (10% → 25% → 40% → 65% → 85% → 100%)
- Hidden endpoint detection: cross-reference JS endpoints vs crawled URLs

### Design Decisions
- gospider over katana: gospider was already installed
- Custom js_analyzer over jsluice/linkfinder: no binary dependency, always available, regex-based is good enough for recon
- Hidden endpoints (in JS but not crawled) are high-value — separated into their own file
- Secret values truncated at 60 chars in output — don't leak full credentials in MCP responses
- gospider capped at 10 hosts, JS analysis at 100 files — prevent runaway on broad domains

### Current Tool Count: 10 MCP tools, 10 tool wrappers

### What's Next
- Phase 3 Day 7: Stage 3 (Analyze) — bughound_get_attack_surface + bughound_submit_scan_plan

---

<!-- APPEND NEW ENTRIES ABOVE THIS LINE -->
<!-- Format: ## YYYY-MM-DD - Day N: Brief Title -->
<!-- Include: Decisions Made, What Was Built, Issues Encountered, What's Next -->
