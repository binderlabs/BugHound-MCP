# BugHound — Future Enhancements

Ideas and plans for features beyond the current Stage 0-5 pipeline.

---

## 1. Auth-Gated Testing (Phase 2)

### Problem
4 of BugTraceAI's 27 findings on bugstore require authentication:
stored XSS (reviews/forum), insecure deserialization (user_prefs cookie),
CSTI on email-preview endpoint. Our pipeline skips these entirely.

### Design: Separate MCP Tools (not part of main pipeline)

```
bughound_auth_login(workspace_id, url)
  → Opens Playwright browser, user logs in manually
  → Captures cookies/tokens after login
  → Saves to workspace auth_session.json

bughound_auth_test(workspace_id, technique)
  → Uses saved auth session
  → Tests auth-gated endpoints (stored_xss, idor_auth, deserialization)
  → Adds findings to scan_results.json

bughound_auth_status(workspace_id)
  → Shows current auth session (logged in? cookies? token expiry?)
```

### Alternative: Token-Based (simpler)
```
bughound_authenticated_scan(workspace_id, auth_token)
  → User provides token from browser dev tools
  → Runs auth-gated techniques with that token
```

### Concerns
- Playwright dependency (fragile on different systems)
- Session/cookie expiry management
- Scope: auth testing opens up CSRF, privilege escalation, session management

### Inspiration
- Rogue (github.com/faizann24/rogue): uses Playwright + AI to control browser
  - `auth_needed()` pauses scan, user logs in, AI continues with session
  - Network traffic proxy captures all requests/responses
  - AI sees rendered DOM, not raw HTML

---

## 2. Network Traffic Proxy

### Problem
SPA apps make API calls via JavaScript that our crawler never sees.
A proxy would capture actual requests when a user interacts with the app.

### Design
- Lightweight mitmproxy or Playwright request interception
- Capture all XHR/fetch requests during user browsing
- Feed captured endpoints into param classifier
- Discover hidden APIs, auth flows, websocket connections

---

## 3. Time-Based Blind SQLi

### Problem
Pure-Python sqli tester only does error-based + HTTP 500 + boolean-blind.
Misses time-based blind SQLi (SLEEP/WAITFOR DELAY).

### Design
- Add Phase 4 to test_sqli: inject `SLEEP(3)`, measure response time
- Compare against baseline response time
- Confirm with second request to rule out network latency
- Add to probe as well (Stage 2)

---

## 4. POST Body Injection Testing

### Problem
Most testers use GET query params. POST forms (login, registration,
comment, file upload) are under-tested.

### Design
- Extract POST endpoints + params from forms.json
- Send POST requests with injection payloads in body
- Support both form-encoded and JSON content types
- Existing post_sqli/post_ssti/post_rce techniques exist but need better param extraction

---

## 5. XXE Testing

### Problem
No XXE technique exists. burpbountylab.com has 3 XXE endpoints we can't test.

### Design
- New technique: xxe_test
- Send POST with XML body containing external entity
- Check for file content in response (blind XXE harder)
- Support both direct and OOB XXE

---

## 6. File Upload Testing

### Problem
No file_upload technique. FILE_UPLOAD_ABUSE chain detected but no testing.

### Design
- New technique: file_upload_test
- Upload files with: double extensions (.php.jpg), content-type bypass,
  null byte injection, webshell content
- Check if uploaded file is accessible/executable

---

## 7. CSRF Detection

### Problem
No CSRF chain or technique. POST forms without CSRF tokens are not flagged.

### Design
- Add CSRF_MISSING chain in Stage 3
- Check forms for absence of CSRF token inputs
- Flag state-changing POST endpoints without CSRF protection

---

## 8. Prototype Pollution Testing

### Problem
Node.js/Express apps vulnerable to prototype pollution not tested.
playbook_to_class maps to "prototype_pollution" but no technique exists.

### Design
- New technique: prototype_pollution_test
- Inject __proto__ payloads in query params and JSON bodies
- Check for behavioral changes in response

---

## 9. Browser-Based Form Testing (Stored XSS)

### Problem
Stored XSS requires: POST payload → read back from different page.
Pure HTTP can do this but needs auth + proper form submission.

### Design (with Playwright)
- Navigate to form page
- Fill form with XSS payload
- Submit form
- Navigate to page where content is displayed
- Check if payload renders in DOM

---

## 10. Smarter Crawling

### Problem
- robots.txt disallowed paths not recursively crawled
- Nested sitemaps not followed
- JS files not priority-sorted before 100 cap
- .js.map source maps partially implemented

### Design
- Feed robots.txt disallowed paths back to katana as seed URLs
- Parse sitemap indexes recursively
- Sort JS files: first-party before third-party, filter CDN libraries
- Full source map parsing for endpoint/secret extraction

---

## 11. Rate Limiting & WAF Evasion

### Problem
- Probes send 500+ requests rapidly, may trigger rate limits
- WAF bypass techniques not implemented

### Design
- Adaptive rate limiting: detect 429/403, back off automatically
- Per-host request counters
- WAF-aware payload selection based on detected WAF type

---

## 12. Default Credential Testing

### Problem
Admin panels found but never tested with default credentials.

### Design
- Per-technology default credential pairs (Tomcat, phpMyAdmin, Grafana, Jenkins)
- Test top 5-10 credentials per discovered admin panel
- Flag as CRITICAL if default creds work

---

## 13. Agentic MCP Enhancements

### Current
- bughound_analyze_host — drill into one host
- bughound_get_immediate_wins — report-ready findings

### Future
- bughound_get_params_for_host(host) — what params to test on this host
- bughound_get_chains_for_host(host) — attack chains for one host
- bughound_compare_hosts(host1, host2) — differential analysis
- bughound_suggest_next_action(workspace_id) — AI guidance on what to do next

---

## 14. Stage 6: Report Generation

### Status: Not built yet — highest priority

### Design
- Generate comprehensive bug bounty report
- Multiple formats: Markdown, HTML, PDF
- Per-finding: description, severity, CVSS, evidence, reproduction steps, remediation
- Executive summary with risk overview
- Include HTML report data from Stage 2 + Stage 3

---

## 15. Performance Optimization

### Problem
Stage 4 testing is slower than necessary due to architectural overhead.

### Bottlenecks (ranked by impact)
1. **17 separate aiohttp sessions** — each test function in injection_tester.py creates its own ClientSession. No TCP/SSL connection reuse across test functions.
2. **No TCPConnector pooling** — every HTTP request opens a fresh TCP + SSL handshake. Should use `TCPConnector(limit=100, limit_per_host=10, ttl_dns_cache=300)`.
3. **Sequential crawling in Stage 2** — hosts crawled one-by-one. 10 hosts × 3 min = 30 min. Should `asyncio.gather()` across hosts.
4. **Heavy semaphore = 2** — only 2 subprocess tools (sqlmap/nuclei) run simultaneously. Could safely raise to 4.
5. **Uniform 5 min technique timeout** — config checks need 30s, injection tests need 120s, only nuclei/sqlmap need 300s.

### Approach
- Create a shared session pool (one session per target host, reused across all techniques)
- Add `TCPConnector` with connection pooling and DNS caching
- Parallelize crawling with `asyncio.gather()` + per-host semaphore
- Per-technique timeout tiers: fast (30s), normal (120s), heavy (300s)
- Bump light_sem 10→15, heavy_sem 2→4

### Risk
High — session pooling changes the HTTP lifecycle for all 42 techniques. Connection leaks, premature session closure, or race conditions would affect the entire testing pipeline. Current per-function session isolation is slower but safe.

### When
After Black Hat demo. Requires thorough integration testing.

---

## 16. CLI Mode (`bughound scan`)

### Problem
Currently BugHound requires an MCP client (gemini-cli, Claude) to run. Users who just want a quick scan shouldn't need to set up MCP.

### Design: 3 execution modes
```
bughound scan <target>              # Automated pipeline, no AI
bughound scan <target> --depth deep # Deep mode
bughound serve                      # MCP server (current mode)
bughound agent <target>             # AI-powered CLI (v2)
```

### CLI Mode (no AI)
- Polished version of `tests/e2e_test.py`
- Same stages, same techniques, same code path as MCP
- Rich terminal output (progress bars, colored findings, summary table)
- Arguments: `--depth`, `--stages`, `--skip-nuclei`, `--output json/html/md`
- Good for CI/CD, quick scans, Black Hat demo

### Agent Mode (built-in AI)
- CLI calls AI API (Anthropic/Google/OpenAI) between stages for reasoning
- AI decides scan plan, prioritizes findings, suggests attack chains
- Two architecture options:
  1. **Direct API calls** — `--provider anthropic --api-key sk-...`
  2. **Claude Agent SDK** — proper agent framework with tool use
- MCP server stays pure (no internal AI) — agent mode is a separate entry point
- Most powerful mode: AI reasons AND acts without human in the loop

### Implementation
- `bughound/cli.py` — argparse entry point
- `bughound/agent.py` — AI agent orchestrator (v2)
- `pyproject.toml` — add `[project.scripts] bughound = "bughound.cli:main"`

---

## 17. V2 Enhancement Areas

### Deeper Testing
- Business logic detection (price tampering, workflow bypass)
- Race condition testing (TOCTOU)
- WebSocket security testing
- OAuth flow analysis
- API schema fuzzing (OpenAPI/Swagger-driven)

### Better Discovery
- Network traffic proxy for SPA API discovery (mitmproxy integration)
- Headless browser-based crawling for JS-heavy apps
- API endpoint inference from mobile app APK analysis
- Subdomain permutation with AI-suggested patterns

### Smarter Analysis
- Finding correlation (group related vulns into attack narratives)
- Auto-triage with AI confidence scoring
- Comparison mode (diff findings between scans)
- Custom nuclei template generation from discovered patterns

### Platform Integration
- HackerOne / Bugcrowd report formatter
- Slack/Discord webhook notifications
- GitHub Issues integration for findings
- Scheduled scanning with cron

---

## Priority Order

### V1 (Black Hat Demo) — DONE
1. ~~Stage 6 (Report)~~ DONE
2. ~~Auth-aware testing~~ DONE (JWT auto-propagation)
3. ~~Time-based blind SQLi~~ DONE
4. ~~POST body injection~~ DONE (form→injection pipeline)
5. ~~XXE technique~~ DONE
6. ~~Config checks~~ DONE (security headers, version disclosure, default creds, etc.)
7. ~~XXE false positive fix~~ DONE
8. ~~Nuclei timeout fix~~ DONE

### V2 (Post-Demo)
1. CLI mode (`bughound scan`) — no AI, automated pipeline
2. Agent mode (`bughound agent`) — built-in AI reasoning
3. Performance optimization — session pooling, parallel crawling
4. Network traffic proxy — SPA API discovery
5. Business logic testing patterns
6. Platform integrations (HackerOne, Slack)
7. Everything else
