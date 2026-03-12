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

## 2026-03-12 - Day 7: Stage 3 (Analyze / Decision Engine)

### Overview
Stage 3 is the intelligence brain of BugHound. Pure data aggregation and pattern matching — no AI calls. Scores targets by real exploitability, detects multi-finding attack chains, surfaces immediate reportable wins, and provides technology-specific playbooks.

### What Was Built

**bughound/stages/analyze.py** (780 lines) — 3 public functions:
1. `get_attack_surface()` — reads all 18 Stage 2 workspace files, builds per-host index, scores exploitability, detects chains
2. `submit_scan_plan()` — validates scope, tool availability, resource limits, stores plan
3. `enrich_target()` — complete intelligence dossier for a single host

**Exploitability Scoring (4-tier weights):**
- CRITICAL (50pts): leaked cloud keys, confirmed takeover, exposed .git, exposed .env
- HIGH (30pts): CORS+creds, Swagger, GraphQL, hidden endpoints, actuator, debug, admin
- MEDIUM (15pts): NO_WAF, OLD_TECH, CORS no-creds, 10+ params, backup files
- LOW (5pts): DEFAULT_PAGE, NON_CDN_IP, few params

Risk levels: CRITICAL (80+), HIGH (50-79), MEDIUM (20-49), LOW (<20)

**12 Attack Chain Patterns:**
1. SOURCE_CODE_THEFT — .git exposed
2. CLOUD_CREDENTIAL_ABUSE — leaked cloud key + cloud resources
3. ACCOUNT_TAKEOVER_CORS — CORS+creds + auth endpoints
4. API_ABUSE_VIA_DOCS — Swagger + hidden endpoints
5. ENV_VARIABLE_LEAK — exposed .env file
6. SUBDOMAIN_TAKEOVER — confirmed/high-confidence dangling DNS
7. UNAUTH_API_INJECTION — hidden endpoints + no WAF
8. DEBUG_INFO_DISCLOSURE — debug mode + actuator/phpinfo
9. WORDPRESS_COMPROMISE — WordPress + old version/wp-admin + no WAF
10. GRAPHQL_EXPLOITATION — GraphQL + no WAF/hidden endpoints
11. INTERNAL_IP_ADMIN_BYPASS — leaked internal IP + 403 admin
12. SHARED_INFRA_PIVOT — shared IP + vulnerability + high-value host

**8 Immediate Win Types (report-ready):**
Subdomain takeover, .git repo, .env file, cloud credentials, CORS critical, actuator, phpinfo, backup files

**5 Technology Playbooks:**
WordPress, GraphQL, Spring Boot, Node.js/Express, React/Angular SPA

**7 Cross-Stage Correlation Types:**
HIDDEN_ENDPOINT, SHARED_INFRASTRUCTURE, LEAKED_CREDENTIAL, TECH_MISMATCH, PARAMETER_HOTSPOT, ROBOTS_HIDDEN

**5 New MCP Tools (16 total):**
- bughound_get_attack_surface — full analysis with scoring, chains, wins, playbooks
- bughound_submit_scan_plan — validate and store scan plan for Stage 4
- bughound_enrich_target — per-host intelligence dossier
- bughound_scope_check — verify target in scope
- bughound_check_tool_coverage — installed tools + install commands

### Current State
- **92 Python files, ~21,600 LOC**
- **16 MCP tools** on single FastMCP server
- **15 tool wrappers** (unchanged from Stage 2)
- **Stages 0-3 fully implemented**

### What's Next
- Phase 3 Day 8: Stage 4 (Test) — bughound_execute_tests + bughound_test_single

---

## 2026-03-13 - Day 8: Stage 4 (Test / Execution Engine)

### Overview
Stage 4 executes the scan plan from Stage 3. Nuclei is the workhorse — no decision-making happens here, tools run exactly what the plan says.

### What Was Built

**nuclei.py rewrite** (419 → 113 lines):
- Migrated from BaseTool class to tool_runner.run() pattern
- Supports: -u (single), -l (file list), -tags, -severity, -t (template path)
- Parses JSONL output into structured finding dicts
- Rate limiting, timeout support, temp file cleanup

**stages/test.py** (362 lines):
- `execute_tests()`: reads scan_plan.json, maps 16 test_classes to nuclei tags, runs priority-ordered
- `test_single()`: surgical single-endpoint testing, scope-checked, always sync
- Finding processing: unique finding_id (sha256 hash), vuln classification, needs_validation flag
- Sync for small plans (≤2 targets, ≤6 classes), async with progress for larger
- 16 test class → nuclei tag mappings (sqli, xss, ssrf, graphql, wordpress, lfi, rfi, redirect, takeover, cve, misconfig, default_creds, exposure, idor, auth_bypass, api)
- Definitive vs needs-validation classification (takeover/exposure/misconfig are definitive; sqli/xss/ssrf need Stage 5)

**2 new MCP tools** (18 total):
- bughound_execute_tests: run full scan plan, sync or async
- bughound_test_single: surgical test one endpoint

### Bug Fixes
- attack_surface.json persistence: DataWrapper expects list, result is dict → use aiofiles directly
- NoneType crash in takeover scoring: `info.get("takeover", {})` returns None → use `(info.get("takeover") or {})`
- Missing workspace_results categories: api_endpoints, dns, js_secrets_confirmed, takeover_confirmed
- Category name mismatches: added aliases (hosts/live_hosts, cors/cors_results, etc.)

### Current State
- **76 Python files, ~20,700 LOC**
- **18 MCP tools** on single FastMCP server
- **15 tool wrappers** (nuclei rewritten)
- **Stages 0-4 fully implemented**

### What's Next
- Phase 4 Day 9: Stage 5 (Validate) + Stage 6 (Report)

---

## 2026-03-13 - Day 8.5: Stage 2-3 Enhancement (Parameter Classification + Directory Discovery)

### Overview
Enhanced Stage 2 discover pipeline with parameter classification (gf-style) and light directory discovery. Enhanced Stage 3 analyze with new attack chains derived from classified parameters.

### What Was Built

**param_classifier.py** (new, 268 lines):
- Pure Python gf-style parameter classification engine
- 8 vulnerability type pattern sets: SQLi, XSS, SSRF, Redirect, LFI, IDOR, RCE, SSTI
- Each type has `exact` name matches + glob `patterns` (fnmatch)
- `classify_parameters()` aggregates from crawled URLs, parameters.json, hidden endpoints
- Outputs per-type candidate lists, high_value_params (match 2+ types), stats

**dir_scanner.py** (new, 242 lines):
- aiohttp-based light directory checking (~200 common paths + tech-specific)
- Technology-aware: WordPress, API, Spring, Node.js path sets
- HEAD requests with semaphore-based concurrency, interesting statuses: 200/301/302/401/403/405
- Generates intelligence flags: ADMIN_PANEL_FOUND, API_DOCS_FOUND, RESTRICTED_PATH, ACTUATOR_FOUND

**discover.py enhancements**:
- Phase 2F: light directory discovery → dirfuzz/light_results.json + flags
- Phase 2G: arjun hidden parameter discovery (if installed) → urls/hidden_parameters.json
- Phase 2H: parameter classification → urls/parameter_classification.json
- `_pick_arjun_targets()` helper: prioritizes hidden endpoints > parameterized URLs > API paths

**analyze.py enhancements**:
- Loads 3 new data files: parameter_classification, dir_findings, hidden_parameters
- 3 new attack chains: MASS_SQLI_PARAMS, SSRF_CLOUD_METADATA, REDIRECT_OAUTH_THEFT
- `_suggest_test_classes()` now derives classes from param classification counts
- `_summarize_param_classification()` and `_summarize_dir_findings()` for attack surface output
- Stats include dir_findings, hidden_parameters, param_classification counts

### What's Next
- Phase 4 Day 9: Stage 5 (Validate) + Stage 6 (Report)

---

## 2026-03-13 - Day 8.75: Enhanced Stage 4 — Technique Library

### Overview
Rebuilt Stage 4 with a 16-technique library, 5-phase execution engine, and pure-Python injection testers. Migrated sqlmap/dalfox/ffuf wrappers to tool_runner pattern.

### What Was Built

**Tool Wrappers Migrated** (sqlmap.py, dalfox.py, ffuf.py):
- All rewritten from old BaseTool class to tool_runner.run() pattern
- sqlmap: --batch, --technique=BEU, parse injectable params + DB type + payloads
- dalfox: JSON output parsing, XSS type classification (reflected/stored/DOM)
- ffuf: wordlist discovery, JSON output, technology-aware wordlist selection

**injection_tester.py** (new, ~450 lines):
- Pure aiohttp injection testing — no external binaries
- 7 testers: test_ssrf, test_open_redirect, test_lfi, test_crlf, test_ssti, test_header_injection, test_idor
- URL parameter replacement (qsreplace logic), baseline comparison, indicator regex matching
- SSRF: 10 cloud metadata + internal IP payloads
- LFI: Linux + Windows traversal payloads
- Header injection: Host poisoning, X-Forwarded-For bypass, X-Original-URL path override

**graphql_tester.py** (new, ~160 lines):
- 5 tests: introspection, depth limits, batch queries, field suggestions, unauthorized mutations
- Full schema extraction when introspection enabled

**jwt_tester.py** (new, ~200 lines):
- 5 tests: alg none bypass, alg confusion (RS256→HS256), empty signature, expiry enforcement, KID injection
- Pure base64url manipulation, no external JWT library

**techniques.py** (new, ~650 lines):
- 16-technique registry with availability checking
- Generic batch runner for injection_tester functions with concurrency control
- Per-technique execution: scope filtering to approved hosts, candidate limiting
- WordPress: xmlrpc, user enum, debug.log checks
- Spring Boot: actuator env/heapdump/mappings/configprops checks

**test.py** (rewritten, ~500 lines):
- 5-phase execution: 4A nuclei → 4B dirfuzz → 4C param discovery → 4D injection → 4E tech-specific
- test_single: now routes to tool= (nuclei/sqlmap/dalfox/ffuf) or technique= (any of 16 techniques)
- Phase stats, tool counts, vuln class counts in output
- bughound_list_techniques: new MCP tool (19 total now)

### Stats
- 83 Python files, ~24K LOC
- 19 MCP tools
- 16 testing techniques (all 16 available with current tool installs)

### What's Next
- Phase 4 Day 9: Stage 5 (Validate) + Stage 6 (Report)

---

## 2026-03-13 - Day 8.9: One-liner Pipeline Engine

### What Was Built

**One-liner tool wrappers (6 wrappers in bughound/tools/oneliners/):**
Each wrapper has BINARY, is_available(), execute() + Python fallback:
- qsreplace.py — replace query param values (Python: urllib.parse manipulation)
- kxss.py — check XSS reflection (Python: aiohttp canary injection)
- gf_tool.py — pattern-based URL filtering (Python: 8 regex pattern sets)
- uro.py — URL deduplication/noise reduction (Python: template normalization)
- unfurl.py — extract URL components: keys, values, paths, domains (Python: urlparse)
- anew.py — append unique lines to file (Python: set-based dedup)

**Pipeline engine (bughound/tools/oneliners/pipeline.py):**
9 pipelines that chain tools for fast pre-filtering:
1. xss_reflection_check — gf(xss) → uro → kxss
2. sqli_candidates_from_urls — gf(sqli) → uro → qsreplace(probe)
3. ssrf_quick_test — gf(ssrf) → uro → qsreplace(metadata URL)
4. redirect_quick_test — gf(redirect) → uro → qsreplace(evil.com)
5. lfi_quick_test — gf(lfi) → uro → qsreplace(traversal)
6. xss_quick_test — gf(xss) → uro → kxss
7. js_secret_extract — filter(.js) → uro → unfurl(paths)
8. param_bruteforce — uro → unfurl(keys)
9. crlf_quick_test — uro → qsreplace(crlf_payload)

**Stage 4 integration (Phase 4D-pre):**
- Pre-filter runs before deep injection testing
- Maps vuln classes to pipelines automatically
- Pipeline candidates inform which URLs to test deeply

**MCP tools (2 new):**
- bughound_run_pipeline — run any of the 9 pipelines
- bughound_list_pipelines — list all pipelines + tool status

**Tool coverage update:**
- oneliner_tools category in bughound_check_tool_coverage
- Install hints in tool_runner.py for all 6 tools

### Stats
- 91 Python files, ~25K LOC
- 21 MCP tools
- 16 testing techniques + 9 one-liner pipelines
- 5/6 one-liner tools installed natively (kxss uses Python fallback)

### What's Next
- Phase 4 Day 9: Stage 5 (Validate) + Stage 6 (Report)

---

## 2026-03-13 - Day 8.95: 4 New One-liner Tools + 8 Smart Pipelines

### What Was Built

**4 new tool wrappers (bughound/tools/oneliners/):**
- gxss.py — reflection check with context analysis (in_script, in_attribute, in_tag, in_comment)
- bhedak.py — upgraded qsreplace with append mode and param targeting
- urldedupe.py — smart URL deduplication by parameter structure (50K URLs → 5K patterns)
- interlace.py — parallel command execution across multiple targets

**8 new smart pipelines (pipeline.py, 17 total):**
1. xss_deep_reflection_check — urldedupe → gf(xss) → gxss (context-aware reflection)
2. mass_ssrf_test — gf(ssrf) → urldedupe → qsreplace(metadata) → httpx(match ami-id)
3. mass_redirect_test — gf(redirect) → urldedupe → bhedak(evil.com) → httpx(match-location)
4. mass_lfi_test — gf(lfi) → urldedupe → qsreplace(traversal) → httpx(match root:x:0)
5. smart_xss_pipeline — urldedupe → gf(xss) → gxss (feeds only in-script/attribute to dalfox)
6. smart_sqli_pipeline — urldedupe → gf(sqli) → qsreplace(probe) → httpx(match sql error)
7. mass_crlf_test — urldedupe → qsreplace(crlf) → httpx(match-header X-Injected)
8. ssti_quick_test — gf(ssti) → urldedupe → qsreplace({{7*7}}) → httpx(match 49)

**Smart pipeline enhancements:**
- _httpx_verify() — pure-Python HTTP verification (body match, header match, location match)
- _smart_dedupe() — global urldedupe pass before every pipeline (biggest single optimization)
- run_prefilter() now prefers smart pipelines when tools available, falls back to basic
- Phase 4D-pre now converts verified hits directly into findings
- Pipeline pre-filter reports urls_before/after_dedupe for optimization stats

**Installation notes:**
- Gxss: go install (Go binary)
- bhedak: pipx install (Python package)
- urldedupe: cmake/make from source (C++ binary)
- interlace: pipx install from GitHub (Python)
- Tool coverage checker updated with all 10 one-liner tools

### Stats
- 95 Python files, ~26K LOC
- 21 MCP tools
- 16 testing techniques + 17 one-liner pipelines
- 10/10 one-liner tools installed natively

### What's Next
- Phase 4 Day 9: Stage 5 (Validate) + Stage 6 (Report)

---

<!-- APPEND NEW ENTRIES ABOVE THIS LINE -->
<!-- Format: ## YYYY-MM-DD - Day N: Brief Title -->
<!-- Include: Decisions Made, What Was Built, Issues Encountered, What's Next -->
