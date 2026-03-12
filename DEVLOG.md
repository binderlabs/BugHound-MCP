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
- 5 MCP servers exist (1 working, 1 broken, 3 stubs)
- 22 tool wrappers, 4 critical bugs, 3 security issues, hardcoded API key

---

## 2026-03-11 - Day 1: Cleanup + Skeleton

### What Was Done
- Removed hardcoded OpenRouter API key (security fix)
- Deleted 9 dead code files, 5 dead directories
- Archived change_detector.py + evidence_collector.py
- Created new project skeleton: server.py, core/, stages/, schemas/, utils/
- Initialized git repo

### Results
- 410 files → 110 files (-300)
- 39,275 LOC → 17,565 LOC (-21,710)

---

## 2026-03-11 - Day 2: Core Infrastructure

### What Was Built
1. **config/settings.py** — TOOL_PATHS, DEFAULT_TIMEOUT, WORKSPACE_BASE_DIR, all env-configurable
2. **core/tool_runner.py** (326 lines) — binary discovery, is_available(), input sanitization, async exec with timeout, structured ToolResult, install hints
3. **core/job_manager.py** (405 lines) — job lifecycle, O(1) index, timeout watchdog, max concurrent limit, cleanup
4. **core/workspace.py** (310 lines) — CRUD, lazy dirs, Pydantic-validated writes, scope checking, metadata management
5. **schemas/models.py** (193 lines) — ToolResult, JobRecord, WorkspaceMetadata, WorkspaceConfig, DataWrapper, TargetType, etc.

---

## 2026-03-11 - Day 3: Stage 0 (Initialize)

### What Was Built
1. **core/target_classifier.py** (167 lines) — classifies BROAD_DOMAIN, SINGLE_HOST, SINGLE_ENDPOINT, URL_LIST. CIDR rejected. Pure input analysis, no network.
2. **server.py** with FastMCP — 4 MCP tools registered:
   - bughound_init, bughound_workspace_list, bughound_workspace_get, bughound_workspace_delete
3. **schemas/models.py** — added TargetClassification model

---

## 2026-03-11 - Day 4: Stage 1 (Enumerate)

### What Was Built
1. **Tool wrappers migrated** (4 tools → tool_runner pattern):
   - subfinder.py (233 → 47 lines), assetfinder.py, findomain.py, crtsh.py (API-based)
2. **tools/recon/dns_resolver.py** (108 lines) — async DNS with dnspython, wildcard detection
3. **stages/enumerate.py** (337 lines):
   - enumerate_light: 4 passive tools in parallel + DNS resolution + pattern analysis
   - enumerate_deep: background job with progress updates
   - Pattern analysis: naming prefixes, IP /24 clustering, interesting targets
4. **5 new MCP tools** (9 total): bughound_enumerate, bughound_enumerate_deep, bughound_job_status, bughound_job_results, bughound_job_cancel

---

## 2026-03-12 - Days 5-6: Stage 2 (Discover) — Complete Build

### Overview
This was the biggest build. Stage 2 discovery now runs 7 phases with 15+ intelligence flags. Multiple rounds of fixes to address gaps and false positives.

### Tool Wrappers Created/Migrated (11 wrappers for Stage 2)

| Wrapper | Lines | Type | Notes |
|---------|-------|------|-------|
| httpx.py | 99 | Migrated | JSONL parsing, batch via temp file, full fingerprint capture |
| wafw00f.py | 65 | Migrated | JSON array extraction from mixed output |
| gau.py | 38 | Migrated | Historical URLs from Wayback/CommonCrawl/OTX |
| waybackurls.py | 36 | Migrated | Historical URLs from Wayback Machine |
| amass.py | 50 | Migrated | Passive mode, JSONL parsing with plain-text fallback |
| gospider.py | 66 | New | Active crawler, JSONL, depth-configurable |
| katana.py | 70 | New | ProjectDiscovery crawler, -js-crawl, JSONL |
| js_analyzer.py | 250 | New | Pure Python, 13 secret patterns, 6 endpoint patterns, confidence scoring |
| sensitive_paths.py | 220 | New | 77+ paths, baseline false-positive filtering, custom validators |
| takeover_checker.py | 182 | New | 25 CNAME fingerprints + nuclei templates |
| cors_checker.py | 139 | New | 3 origin payloads, 5 severity levels |

### Stage 1 Enhancement
- Added amass to parallel enumeration → 5 passive tools now (subfinder, assetfinder, findomain, crtsh, amass)

### Discovery Pipeline — 7 Phases

```
10% - Phase 2A: httpx probe (live host detection + fingerprinting)
20% - Phase 2A: wafw00f WAF/CDN detection
30% - Phase 2A: Intelligence flag generation
35% - Phase 2B: URL discovery (gau + waybackurls + katana/gospider in parallel)
50% - Phase 2B: JS analysis (download, extract secrets + endpoints, hidden endpoint detection)
65% - Phase 2C: Sensitive path checks (77+ paths per host with baseline comparison)
80% - Phase 2D: Subdomain takeover detection (CNAME fingerprinting + nuclei)
90% - Phase 2E: CORS misconfiguration probing
95% - Parameter aggregation + final analysis
100% - Complete
```

### Intelligence Flags (15+ types)
**From Phase 2A:** NO_WAF, NON_CDN_IP, DEFAULT_PAGE, GRAPHQL, OLD_TECH, DEBUG_MODE
**From Phase 2C:** GIT_EXPOSED, ENV_LEAKED, SWAGGER_EXPOSED, GRAPHQL_INTROSPECTION, ADMIN_PANEL, DEBUG_ENABLED, SPRING_ACTUATOR, BACKUP_FOUND, CONFIG_LEAKED, SVN_EXPOSED, INFO_LEAK
**From Phase 2E:** CORS_MISCONFIGURED (with severity: CRITICAL/HIGH/MEDIUM/LOW/INFO)

### JS Analyzer Secret Patterns (13 patterns, confidence-scored)
**HIGH:** AWS_ACCESS_KEY, AWS_SECRET_KEY, GOOGLE_API, SLACK_TOKEN, GITHUB_TOKEN, PRIVATE_KEY, JWT, FIREBASE, S3_BUCKET
**MEDIUM:** API_KEY, BEARER_TOKEN, INTERNAL_IP
**LOW:** GENERIC_SECRET (12+ char minimum, false-positive filtered)

### Workspace Output Files (Stage 2)
- hosts/live_hosts.json, hosts/technologies.json, hosts/waf.json, hosts/flags.json
- hosts/sensitive_paths.json, hosts/cors_results.json
- urls/crawled.json, urls/js_files.json, urls/parameters.json, urls/robots_sitemap.json
- secrets/js_secrets.json, secrets/js_secrets_confirmed.json (HIGH+MEDIUM only)
- endpoints/api_endpoints.json, endpoints/hidden_endpoints.json
- cloud/takeover_candidates.json, cloud/takeover_confirmed.json

### Bug Fixes During Build
1. **stdin=DEVNULL** — httpx hung in MCP stdio mode because child process inherited JSON-RPC stdin
2. **Workspace path** — Changed from source tree to `./bughound-workspaces/` in CWD; removed `cwd` from gemini config
3. **Human-friendly output** — Rewrote all MCP tool returns from raw JSON to formatted markdown
4. **Per-tool URL breakdown** — Added tool-by-tool URL count to discover output
5. **Sensitive path false positives** — Added baseline comparison (random path request) to filter catch-all routes
6. **CORS null severity** — Fixed null origin without credentials from MEDIUM to INFO
7. **JS analyzer false positives** — Added confidence scoring, minimum 12-char value length, minified JS fragment detection

### Testing
- **scanme.nmap.org** (single host): 1 live host, Apache 2.4.7, 117 URLs, 1 Google API key, 2 hidden endpoints
- **pro.odaha.io** (single host): 1 live host, ASP.NET 2.0.50727, jQuery 1.4.3, Azure CDN, 54 URLs
- **bugtraceai.com** (broad domain): 3 subdomains, 3 live hosts, 81 URLs, GraphQL on bugstore, .env exposed on all 3 hosts, Swagger docs, CORS wildcard with credentials on bugstore, Dockerfile on demo

### Current State
- **94 Python files, ~21,000 LOC**
- **10 MCP tools** on single FastMCP server
- **15 tool wrappers** (6 recon + 5 discovery + 4 scanning unchanged)
- **Stages 0-2 fully implemented and tested**
- **gemini-cli integration working** (tested with real targets)

### What's Next
- Phase 3 Day 7: Stage 3 (Analyze) — bughound_get_attack_surface + bughound_submit_scan_plan

---

<!-- APPEND NEW ENTRIES ABOVE THIS LINE -->
<!-- Format: ## YYYY-MM-DD - Day N: Brief Title -->
<!-- Include: Decisions Made, What Was Built, Issues Encountered, What's Next -->
