# BugHound MCP Workflow

## Complete Tool Inventory

```
┌─────────────────────────────────────────────────────────────────┐
│                    BUGHOUND MCP SERVER                           │
│                    (single server, ~15 tools)                    │
│                                                                  │
│  WORKSPACE          JOBS             RECON                       │
│  ──────────         ────             ─────                       │
│  bughound_init      bughound_        bughound_enumerate          │
│  bughound_          job_status       bughound_enumerate_deep     │
│   workspace_list    bughound_        bughound_discover           │
│  bughound_          job_results                                  │
│   workspace_get     bughound_        INTELLIGENCE                │
│  bughound_          job_cancel       ────────────                │
│   workspace_delete                   bughound_get_attack_surface │
│                                      bughound_submit_scan_plan   │
│  UTILITY                             bughound_recon_summary      │
│  ───────                             bughound_enrich_target      │
│  bughound_                           bughound_scope_check        │
│   check_tool_                        bughound_check_tool_        │
│   coverage                            coverage                   │
│                                                                  │
│  TESTING            VALIDATION       REPORTING                   │
│  ───────            ──────────       ─────────                   │
│  bughound_          bughound_        bughound_generate_report    │
│   execute_tests      validate_                                   │
│  bughound_           finding                                     │
│   test_single                                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Workflow 1: Broad Domain Full Recon

This is the primary workflow. User targets a wildcard domain.

```
USER: "Run full recon on example.com"

AI CLIENT                              MCP SERVER                    WORKSPACE
─────────                              ──────────                    ─────────
    │                                       │                            │
    │─── bughound_init ───────────────────>│                            │
    │    target: "example.com"              │── classify target          │
    │    depth: "light"                     │── create workspace ──────>│ metadata.json
    │<── workspace_id: "example_com_a1b2"   │                           │ config.json
    │    type: BROAD_DOMAIN                 │                            │
    │    stages: [0,1,2,3,4,5,6]            │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_enumerate ──────────────>│                            │
    │    workspace_id: "example_com_a1b2"   │── subfinder ──────────>   │
    │                                       │── assetfinder ────────>   │
    │                                       │── findomain ──────────>   │
    │                                       │── crt.sh API ─────────>   │
    │                                       │── DNS resolution          │
    │                                       │── deduplicate             │
    │                                       │── pattern analysis        │
    │<── 247 subdomains found               │────────────────────────>  │ subdomains/all.txt
    │    patterns: ["dev-*", "api-*"]       │                           │ subdomains/sources.json
    │    anomalies: ["3 non-CDN IPs"]       │                           │ dns/records.json
    │                                       │                            │
    │                                       │                            │
    │  AI THINKS: "dev-* and api-* patterns │                            │
    │  detected. 3 hosts not behind CDN     │                            │
    │  are interesting. Let me discover."    │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_discover ───────────────>│                            │
    │    workspace_id: "example_com_a1b2"   │── httpx (probe all) ──>   │
    │                                       │── wafw00f ────────────>   │
    │                                       │── gospider (crawl) ───>   │
    │                                       │── gau + waybackurls ──>   │
    │                                       │── jsluice (JS) ───────>   │
    │                                       │── ffuf (dirfuzz) ─────>   │
    │<── job_id: "job_disc_xyz"             │────────────────────────>  │ hosts/live_hosts.json
    │    (async, broad target)              │                           │ hosts/technologies.json
    │                                       │                           │ urls/crawled.json
    │                                       │                           │ secrets/js_secrets.json
    │                                       │                            │
    │─── bughound_job_status ─────────────>│                            │
    │    job_id: "job_disc_xyz"             │── check progress          │
    │<── status: "running", progress: 65%   │                            │
    │                                       │                            │
    │    ... (AI waits or does other work)   │                            │
    │                                       │                            │
    │─── bughound_job_status ─────────────>│                            │
    │<── status: "completed"                │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_get_attack_surface ─────>│                            │
    │    workspace_id: "example_com_a1b2"   │── read all Stage 2 data   │
    │                                       │── compute stats           │
    │                                       │── find patterns           │
    │                                       │── identify anomalies      │
    │<── attack_surface_summary:            │                            │
    │    89 live hosts                      │                            │
    │    7 secrets in JS                    │                            │
    │    GraphQL on api.example.com         │                            │
    │    WordPress 6.3 on blog.example.com  │                            │
    │    3 takeover candidates              │                            │
    │    leaked AWS key in /static/app.js   │                            │
    │                                       │                            │
    │                                       │                            │
    │  AI THINKS: "api.example.com has      │                            │
    │  GraphQL with no WAF, 15 params,      │                            │
    │  leaked AWS key. Priority 1.          │                            │
    │  blog.example.com has WordPress 6.3,  │                            │
    │  check for plugin vulns. Priority 2.  │                            │
    │  3 takeover candidates. Priority 3."  │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_submit_scan_plan ───────>│                            │
    │    targets: [                         │── validate scope          │
    │      {api.example.com, p1,            │── check tools exist       │
    │       [sqli,xss,graphql,ssrf]},       │── store plan ──────────> │ scan_plan.json
    │      {blog.example.com, p2,           │                            │
    │       [wordpress,sqli,xss]},          │                            │
    │      {takeover candidates, p3,        │                            │
    │       [subdomain_takeover]}           │                            │
    │    ]                                  │                            │
    │<── plan approved                      │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_execute_tests ──────────>│                            │
    │    workspace_id: "example_com_a1b2"   │── read scan_plan.json     │
    │                                       │── nuclei (graphql tags)   │
    │                                       │── nuclei (wordpress tags) │
    │                                       │── nuclei (takeover tags)  │
    │<── 12 findings                        │────────────────────────>  │ vulns/scan_results.json
    │    3 critical, 4 high, 5 medium       │                            │
    │                                       │                            │
    │                                       │                            │
    │  AI THINKS: "3 critical findings.     │                            │
    │  SQLi on api.example.com/users?id=    │                            │
    │  XSS on blog.example.com/search?q=   │                            │
    │  Let me validate these."              │                            │
    │                                       │                            │
    │                                       │                            │
    │─── bughound_validate_finding ───────>│                            │
    │    finding_id: "sqli_001"             │── sqlmap --batch          │
    │    tool: "sqlmap"                     │── capture evidence        │
    │<── CONFIRMED, MySQL injection         │────────────────────────>  │ vulns/confirmed/
    │    poc: full request/response          │                            │
    │                                       │                            │
    │─── bughound_validate_finding ───────>│                            │
    │    finding_id: "xss_001"              │── dalfox --skip-bav       │
    │    tool: "dalfox"                     │── capture evidence        │
    │<── CONFIRMED, reflected XSS           │────────────────────────>  │ vulns/confirmed/
    │                                       │                            │
    │                                       │                            │
    │─── bughound_generate_report ────────>│                            │
    │    workspace_id: "example_com_a1b2"   │── read all data           │
    │    type: "bug_bounty"                 │── format per finding      │
    │<── report markdown                    │────────────────────────>  │ reports/bug_bounty.md
    │                                       │                            │
    │  AI: "Here's your report with 5       │                            │
    │  confirmed findings ready for         │                            │
    │  submission."                          │                            │
    │                                       │                            │
```

---

## Workflow 2: Single Host Quick Scan

User targets a specific subdomain. Fast, surgical.

```
USER: "Quick scan dev.example.com"

AI CLIENT                              MCP SERVER
─────────                              ──────────
    │                                       │
    │─── bughound_init ───────────────────>│
    │    target: "dev.example.com"          │
    │<── type: SINGLE_HOST                  │
    │    stages: [0,2,3,4,5,6]              │  (Stage 1 SKIPPED)
    │                                       │
    │─── bughound_discover ───────────────>│
    │    (SYNCHRONOUS - single host)        │── httpx probe
    │                                       │── wafw00f
    │                                       │── gospider crawl
    │                                       │── gau + waybackurls
    │                                       │── jsluice
    │<── direct results (no job_id)         │
    │    tech: [React, Express, Node.js]    │
    │    42 URLs, 8 params, 2 JS secrets    │
    │                                       │
    │─── bughound_get_attack_surface ─────>│
    │<── single host summary                │
    │                                       │
    │  AI: Decides what to test             │
    │                                       │
    │─── bughound_submit_scan_plan ───────>│
    │─── bughound_execute_tests ──────────>│
    │─── bughound_validate_finding ───────>│
    │─── bughound_generate_report ────────>│
    │                                       │
    │  Total time: ~5 minutes               │
```

---

## Workflow 3: AI Feedback Loop (Re-entry)

The AI finds something interesting and re-enters earlier stages.

```
USER: (during active scan)

AI CLIENT                              MCP SERVER
─────────                              ──────────
    │                                       │
    │  (Stage 4 completed, reviewing        │
    │   scan results...)                    │
    │                                       │
    │  AI THINKS: "Found SQLi on            │
    │  /api/v1/users. There might be more   │
    │  API endpoints I haven't discovered.  │
    │  Let me enrich this specific host."   │
    │                                       │
    │─── bughound_enrich_target ──────────>│
    │    host: "api.example.com"            │── gather all known data
    │<── complete picture:                  │   about this host
    │    endpoints: /api/v1/users,          │
    │               /api/v1/admin,          │
    │               /api/v2/...             │
    │    Note: /api/v2/ found in JS but     │
    │    never crawled                      │
    │                                       │
    │  AI: "/api/v2/ was never tested!      │
    │  Let me test it directly."            │
    │                                       │
    │─── bughound_test_single ────────────>│
    │    target: "api.example.com/api/v2/"  │── nuclei against
    │    tool: "nuclei"                     │   /api/v2/ specifically
    │<── 2 new findings on /api/v2/         │
    │                                       │
    │  AI: "Found more vulns on v2 API.     │
    │  Let me also check if v3 exists."     │
    │                                       │
    │─── bughound_scope_check ────────────>│
    │    target: "api.example.com"          │── check against config.json
    │<── in_scope: true                     │   scope rules
    │                                       │
    │  (AI continues iterating...)          │
```

---

## Workflow 4: Adaptive Tool Selection

The AI adapts when tools are unavailable.

```
AI CLIENT                              MCP SERVER
─────────                              ──────────
    │                                       │
    │─── bughound_check_tool_coverage ────>│
    │                                       │── check all binaries
    │<── available:                         │
    │      subfinder: YES                   │
    │      httpx: YES                       │
    │      nuclei: YES                      │
    │      gospider: NO                     │
    │      jsluice: NO                      │
    │      ffuf: YES                        │
    │      sqlmap: YES                      │
    │      dalfox: NO                       │
    │                                       │
    │  AI ADAPTS:                           │
    │  "No gospider - use gau + waybackurls │
    │  for URL discovery instead.           │
    │  No jsluice - skip JS analysis or     │
    │  use grep-based extraction.           │
    │  No dalfox - use nuclei XSS templates │
    │  for validation instead."             │
    │                                       │
    │  (AI adjusts its entire strategy      │
    │   before calling any recon tool)      │
```

---

## MCP Tool Quick Reference

| Tool | Stage | Sync/Async | Purpose |
|------|-------|-----------|---------|
| `bughound_init` | 0 | Sync | Classify target, create workspace |
| `bughound_workspace_list` | 0 | Sync | List all workspaces |
| `bughound_workspace_get` | 0 | Sync | Get workspace details |
| `bughound_workspace_delete` | 0 | Sync | Delete workspace |
| `bughound_enumerate` | 1 | Sync | Light subdomain enumeration |
| `bughound_enumerate_deep` | 1 | Async | Deep subdomain enumeration |
| `bughound_discover` | 2 | Both* | Full attack surface discovery |
| `bughound_job_status` | Any | Sync | Poll background job |
| `bughound_job_results` | Any | Sync | Get completed job results |
| `bughound_job_cancel` | Any | Sync | Cancel running job |
| `bughound_get_attack_surface` | 3 | Sync | Get AI-optimized summary |
| `bughound_submit_scan_plan` | 3 | Sync | Submit AI's scan plan |
| `bughound_recon_summary` | 2-3 | Sync | Recon-phase AI briefing |
| `bughound_enrich_target` | Any | Sync | All data for one host |
| `bughound_scope_check` | Any | Sync | Is target in scope? |
| `bughound_check_tool_coverage` | Any | Sync | What tools are installed? |
| `bughound_execute_tests` | 4 | Both* | Execute scan plan |
| `bughound_test_single` | 4 | Sync | Surgical single-target test |
| `bughound_validate_finding` | 5 | Sync | Validate one finding |
| `bughound_generate_report` | 6 | Sync | Generate report |

*Both = sync for single host, async for broad domain
