# BugHound 10-Day Development Plan

Target: Black Hat Arsenal demo-ready by Day 10

## Phase 0: Foundation (Days 1-2)

### Day 1: Cleanup + Project Skeleton

**Cleanup (delete dead code):**
- [x] Rotate/remove hardcoded OpenRouter API key from config.py
- [x] Delete: commander_server.py
- [x] Delete: workflow_engine.py
- [x] Delete: ai_analyzer.py
- [x] Delete: ai_client.py
- [x] Delete: prioritization_engine.py
- [x] Delete: prompts/recon_analysis.py
- [x] Delete: scan_modes.py
- [x] Delete: recon_server.py.bak
- [x] Delete: phase2_test.log
- [x] Delete: literal dash-named files (bughound/- and BugHound/-)
- [x] Delete: backups/ directory (full source duplicate)
- [x] Delete: docs/legacy_plans/ directory
- [x] Delete: bughound/scripts/ (manual test scripts)
- [x] Delete: duplicate config/ directory at project root
- [x] Delete: old workspaces in workspaces/
- [x] Archive (move to _archive/): change_detector.py
- [x] Archive (move to _archive/): evidence_collector.py

**New project skeleton:**
- [x] Create bughound/server.py (single MCP server entry point)
- [x] Create bughound/config/settings.py
- [x] Create bughound/core/ directory with __init__.py
- [x] Create bughound/stages/ directory with __init__.py
- [x] Create bughound/schemas/ directory with __init__.py
- [x] Create bughound/utils/ directory with __init__.py
- [x] Move existing tool wrappers into new bughound/tools/ structure
- [x] Init git repo
- [x] First commit: "clean slate"

### Day 2: Core Infrastructure + Context Files

**Context survival setup:**
- [x] CLAUDE.md in project root (copy from setup files)
- [x] .claude/skills/ directory with all skill files
- [x] DEVLOG.md initialized
- [x] PLAN.md (this file) in project root
- [x] Install context-manager agent

**Core infrastructure (3 critical files):**
- [x] core/tool_runner.py: unified subprocess runner
  - Binary discovery with configurable PATH
  - Pre-flight is_available() check
  - Async execution with timeout
  - Structured error responses
  - Input sanitization (no shell injection)
- [x] core/job_manager.py: async job lifecycle
  - Create job with unique ID
  - Status tracking with real percentage
  - Configurable timeout per job
  - Job cancellation support
  - Job-to-workspace linking (indexed, not linear scan)
  - Cleanup of old completed jobs
- [x] core/workspace.py: new workspace management
  - Data-type-based directory structure
  - Lazy directory creation
  - Pydantic schema validation on writes
  - metadata.json + config.json separation
  - Workspace CRUD operations
- [x] Git commit: "core infrastructure"

## Phase 1: Stage 0 + Stage 1 (Days 3-4)

### Day 3: Stage 0 (Initialize)

- [ ] core/target_classifier.py
  - Detect: BROAD_DOMAIN, SINGLE_HOST, SINGLE_ENDPOINT, URL_LIST
  - Return classification with stages_to_run
- [ ] Register MCP tools in server.py:
  - [ ] bughound_init (classify + create workspace)
  - [ ] bughound_workspace_list
  - [ ] bughound_workspace_get
  - [ ] bughound_workspace_delete
- [ ] Test end-to-end: create workspace for each target type
- [ ] Git commit: "stage 0 - initialize"

### Day 4: Stage 1 (Enumerate)

- [ ] stages/enumerate.py orchestration module
- [ ] Migrate tool wrappers to new tool_runner base:
  - [ ] subfinder
  - [ ] assetfinder
  - [ ] findomain
  - [ ] crtsh (API-based)
- [ ] Light enumeration: parallel passive sources + DNS resolution
- [ ] Deep enumeration: async job with bruteforce + permutations
- [ ] Auto-skip for non-BROAD_DOMAIN targets
- [ ] Register MCP tools:
  - [ ] bughound_enumerate (sync, light)
  - [ ] bughound_enumerate_deep (async, deep)
  - [ ] bughound_job_status (generic job polling)
  - [ ] bughound_job_results (generic result retrieval)
  - [ ] bughound_job_cancel (generic job cancellation)
- [ ] Output: subdomains/all.txt, subdomains/sources.json, dns/records.json
- [ ] Test: enumerate on real target, verify output
- [ ] Git commit: "stage 1 - enumerate"

**Day 4 Checkpoint:** target input -> classification -> workspace -> enumerated subdomains

## Phase 2: Stage 2 (Days 5-6)

### Day 5: Discover - Probing + Fingerprinting

- [ ] stages/discover.py orchestration module
- [ ] Migrate tool wrappers:
  - [ ] httpx (probe + fingerprint)
  - [ ] wafw00f (WAF detection)
- [ ] Probing as noise filter (tag parked/dead/redirect-only hosts)
- [ ] Register MCP tool:
  - [ ] bughound_discover (sync for single host, async for broad)
- [ ] Output: hosts/live_hosts.json, hosts/technologies.json, hosts/waf.json
- [ ] Git commit: "stage 2a - probe and fingerprint"

### Day 6: Discover - URLs + JS + Secrets

- [ ] Migrate/create tool wrappers:
  - [ ] gau (historical URLs)
  - [ ] waybackurls (historical URLs)
  - [ ] gospider OR katana (crawler) -- pick whichever installs cleanly
  - [ ] jsluice OR linkfinder (JS analysis) -- pick whichever works
- [ ] Parameter harvesting from discovered URLs
- [ ] JS secret extraction
- [ ] Output: urls/crawled.json, urls/parameters.json, secrets/js_secrets.json
- [ ] Git commit: "stage 2b - discovery complete"

**HARD RULE: if a new tool wrapper takes more than 2 hours, skip it. Use existing gau + waybackurls as fallback for URL discovery.**

**Day 6 Checkpoint:** full attack surface map exists in workspace

## Phase 3: Stage 3 + Stage 4 (Days 7-8)

### Day 7: Stage 3 (Analyze / Decision Engine)

- [ ] stages/analyze.py
- [ ] Build attack surface summary aggregation:
  - Read all Stage 2 data
  - Compute stats (subdomain count, live hosts, tech inventory, etc.)
  - Identify high-interest targets (simple heuristic: endpoints + params + secrets)
  - Format as clean JSON for AI consumption
- [ ] Scan plan validation:
  - Check targets against scope
  - Check referenced tools exist
  - Store approved plan in workspace
- [ ] Register MCP tools:
  - [ ] bughound_get_attack_surface
  - [ ] bughound_submit_scan_plan
- [ ] Git commit: "stage 3 - analyze"

### Day 8: Stage 4 (Test)

- [ ] stages/test.py
- [ ] Migrate nuclei wrapper to new tool_runner base
- [ ] Map test_classes from scan plan to nuclei template tags
- [ ] Execute scan plan against approved targets
- [ ] Register MCP tools:
  - [ ] bughound_execute_tests (async for broad, sync for single)
  - [ ] bughound_test_single (surgical, always sync)
- [ ] Output: vulnerabilities/scan_results.json
- [ ] Git commit: "stage 4 - test"

**Day 8 Checkpoint:** full pipeline works: target -> recon -> AI analysis -> vulnerability scanning

## Phase 4: Stage 5 + Stage 6 + Polish (Days 9-10)

### Day 9: Validation + Reporting

**Stage 5 (Validate):**
- [ ] stages/validate.py
- [ ] Migrate sqlmap wrapper
- [ ] Migrate dalfox wrapper
- [ ] Register MCP tool:
  - [ ] bughound_validate_finding
- [ ] Output: vulnerabilities/validated.json, vulnerabilities/confirmed/

**Stage 6 (Report):**
- [ ] stages/report.py
- [ ] Migrate existing report_generator.py to new structure
- [ ] Bug bounty report template (must-have)
- [ ] Technical report template (nice-to-have)
- [ ] Register MCP tool:
  - [ ] bughound_generate_report
- [ ] Git commit: "stages 5-6 - validate and report"

### Day 10: End-to-End Testing + Demo Prep

**HARD FEATURE FREEZE. No new features.**

- [ ] Test full pipeline on real authorized target
- [ ] Fix broken functionality
- [ ] Clean up console output, debug logs, error messages
- [ ] Write demo script (exact prompts for Arsenal presentation)
- [ ] Practice demo flow
- [ ] Update README.md with installation + quick start
- [ ] Final git commit: "v1.0 - arsenal ready"

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| New tool wrapper takes too long (Day 5-6) | Delays Stage 2 | 2-hour hard limit per wrapper, use existing tools as fallback |
| Nuclei template mapping is complex (Day 8) | Delays Stage 4 | Start with broad template categories, refine later |
| Cross-client MCP compatibility issues | Demo breaks | Test on primary client only, test others post-demo |
| Scope creep after Day 8 | Miss deadline | Hard feature freeze Day 10, no exceptions |
| Deep recon async jobs are fragile | Demo crashes | Demo with light recon only, deep is bonus |

## Demo Priorities (if running out of time)

Must-have for demo:
1. bughound_init (target classification)
2. bughound_enumerate (light, sync)
3. bughound_discover (probe + URL discovery)
4. bughound_get_attack_surface (AI reasoning moment)
5. bughound_execute_tests (nuclei scan)
6. bughound_generate_report (bug bounty format)

Nice-to-have:
7. bughound_enumerate_deep (async background job)
8. bughound_validate_finding (sqlmap/dalfox confirmation)
9. bughound_test_single (surgical testing)
10. Deep dirfuzz, JS analysis, cloud enumeration
