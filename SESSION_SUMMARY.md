# BugHound — Session Summary (2026-03-18)

## What We Built

BugHound is an MCP server for AI-powered bug bounty reconnaissance and vulnerability assessment. The AI client (Gemini, Claude, etc.) orchestrates a 7-stage pipeline by calling MCP tools.

---

## Pipeline Overview

```
Stage 0: Init        → Target classification + workspace creation
Stage 1: Enumerate   → Subdomain discovery (broad_domain only)
Stage 2: Discover    → Probe, crawl, classify params, live reflection probes
Stage 3: Analyze     → Score hosts, attack chains, reasoning prompts for AI
Stage 4: Test        → Nuclei + 33 parallel injection techniques
Stage 5: Validate    → Surgical verification (background job)
Stage 6: Report      → NOT YET BUILT
```

---

## Target Types

| Type | Example | Stage 1 | Crawl Depth | Probe Limit |
|------|---------|---------|-------------|-------------|
| Single Host | https://pro.odaha.io | Skipped | Deep (3) | 60 |
| Broad Domain | bugtraceai.com | Runs | Shallow (1) | min(500, hosts*10) |
| Single Endpoint | https://example.com/api | Skipped | From path only | 60 |
| URL List | file with URLs | Skipped | Per-URL | 60 |

### Light vs Deep (Stage 1 only)
- **Light (default)**: subfinder + assetfinder + crtsh + findomain (~30-60s)
- **Deep (user asks)**: above + amass + gotator permutations + puredns bruteforce (~5-15min)

### Broad Domain User Flow
```
Stage 1 → finds 100 subdomains → shows list to user
User picks: "focus on api and staging"
Stage 2 → runs on selected subdomains only (fast)
OR user says "scan all" → shallow crawl on all
```

---

## What Makes BugHound Different

### 1. Live Reflection Probes (Stage 2)
Before testing even starts, Stage 2 sends lightweight HTTP probes to every parameter:
- XSS: inject marker, check if reflected in HTML
- SQLi: inject single quote, check for SQL errors OR HTTP 500
- LFI: inject path traversal, check for /etc/passwd indicators

Probe-confirmed params get highest priority in Stage 4. This means the AI client sees "CONFIRMED SQLi on /api/products/?search=" before deciding what to test.

### 2. Reasoning Prompts (Stage 3)
The MCP server generates context-aware prompts that guide the AI client's thinking — without any internal AI calls:
```
"pro.odaha.io has CONFIRMED SQL injection. Consider: what database? Can you extract credentials?"
"No WAF protection and 19 injectable params. Direct exploitation possible."
"jQuery 1.4.3 — check for prototype pollution CVEs."
```

### 3. 33 Techniques, 29 Pure-Python
Works without any external tools installed. sqlmap, dalfox, nuclei enhance results but are optional.

### 4. DOM XSS via Playwright
Headless Chrome renders SPAs, detects DOM-based XSS that server-side testing misses.

---

## 33 Testing Techniques

### External Tools (4)
| Technique | Tool |
|-----------|------|
| nuclei_scan | nuclei — template-based CVE/misconfig scanning |
| sqli_param_fuzz | sqlmap — deep SQLi exploitation |
| xss_param_fuzz | dalfox — advanced XSS fuzzing |
| deep_dirfuzz | ffuf — directory brute-force |

### Pure-Python (29)
| Category | Techniques |
|----------|-----------|
| SQLi | sqli_error_test (error-based + boolean-blind + HTTP 500), cookie_sqli, post_sqli |
| XSS | reflected_xss_test, dom_xss (Playwright), stored_xss, cookie_xss |
| SSRF | ssrf_test (indicators + massive size change for redirect-based) |
| LFI | lfi_test (traversal payloads + baseline comparison) |
| SSTI | ssti_test (anti-echo false positive filter), post_ssti |
| CSTI | csti_test (AngularJS/Vue.js, 1337*7=9359) |
| IDOR | idor_test (param), path_idor_test (REST path inference) |
| RCE | rce_test (time-based + output-based), post_rce |
| Access | broken_access_control (16 admin paths + verb tampering + path bypass) |
| Other | open_redirect, crlf, header_injection, rate_limit, mass_assignment, cors_misconfig, jwt_test, graphql_test, wordpress_test, spring_actuator_test, cookie_deserialization |

---

## Test Results

### pro.odaha.io (Traditional HTML/ASP.NET app)
| Finding | Count |
|---------|-------|
| SQLi (error-based) | 3 |
| Reflected XSS | 2 |
| LFI | 4 |
| RCE | 1 |
| IDOR | 2 |
| BAC | 1 |
| Nuclei CVEs | 8 |
| **Total** | **25 unique** |

### bugstore.bugtraceai.com (Modern SPA/JSON API)
| Finding | Count |
|---------|-------|
| SQLi (HTTP 500) | 1 |
| DOM XSS (Playwright) | 1 |
| SSRF (redirect-based) | 1 |
| IDOR (REST path) | 4 |
| Open Redirect | 1 |
| BAC | 2 |
| CORS | 1 |
| Rate Limiting | 22 |
| Nuclei | ~10 |
| **Total** | **~44 unique** |

### Coverage vs BugTraceAI (27 validated findings on bugstore)
| Status | Count | Details |
|--------|-------|---------|
| BugHound finds | 9/13 | SQLi, SSRF, IDOR x4, redirect, DOM XSS, BAC |
| Needs auth | 4/13 | Stored XSS x2, deserialization, CSTI on email-preview |

---

## Major Fixes This Session

### Critical Bugs Fixed
1. **Header key casing** — `Content-Type` vs `content-type` broke ALL XSS/content detection
2. **SSTI false positive** — JSON APIs echo payload in error messages, not template execution
3. **HTTP 500 SQLi** — JSON APIs return 500 not SQL error text on injection
4. **Probe candidate ordering** — high-value params (search, id, query) probed first
5. **Technique timeout** — 15/27 techniques hung indefinitely, now 5min max
6. **DOM XSS params** — search/q/query prioritized for Playwright testing
7. **Candidate sorting** — probe-confirmed sorted BEFORE scope limit cuts them
8. **Path traversal security** — workspace_id and data path validation
9. **Temp file cleanup** — puredns/gotator temp files now cleaned up

### Features Added
1. **Pure-Python SQLi tester** (error-based + boolean-blind + HTTP 500)
2. **Pure-Python reflected XSS tester** (marker + payload + context detection)
3. **CSTI technique** (AngularJS/Vue.js template injection)
4. **CORS promotion** (Stage 2 CORS → Stage 4 findings)
5. **REST path IDOR inference** (/api/orders/ → test /api/orders/1)
6. **Parameterless endpoint inference** (debug/admin URLs get test params)
7. **Live reflection probes** (behavior-based param classification)
8. **Reasoning prompts** (AI-guided analysis)
9. **Finding deduplication** (78 raw → 15 unique)
10. **Playwright DOM XSS** (driver auto-patching)
11. **puredns + gotator integration** (deep enumerate)
12. **Broad domain support** (scope, probe scaling, crawl depth, target selection)
13. **Output formatting** (terminal-style, no emojis, clean tables)

---

## Known Limitations

1. **No auth-aware testing** — can't test stored XSS, deserialization, protected CSTI
2. **DOM XSS requires Playwright** — heavy, needs Node.js + Chromium
3. **No Stage 6 (Report)** — pipeline has no final deliverable yet
4. **Time-based blind SQLi** — pure-Python tester doesn't do SLEEP detection (sqlmap handles it)
5. **POST body testing** — limited, most testers use GET params
6. **Broad domain scale** — 100+ subdomains still slow

---

## What's Next (Priority Order)

1. **Stage 6: Report generation** — required for Black Hat demo
2. **Auth-aware testing** — auto-register, use tokens for protected endpoints
3. **Full E2E verification** — run on both targets, verify all findings
4. **POST body injection** — test form submissions, JSON body params
5. **Time-based blind SQLi** — SLEEP-based detection in pure-Python
6. **Broad domain optimization** — parallel host crawling
