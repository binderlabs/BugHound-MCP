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

## Priority Order

1. Stage 6 (Report) — required for Black Hat demo
2. Auth-gated testing — +4 findings on bugstore alone
3. Time-based blind SQLi — most common real-world SQLi
4. POST body injection — login/form testing
5. XXE technique — missing vulnerability class
6. Network traffic proxy — SPA API discovery
7. Everything else
