<p align="center">
  <img src="assets/bughound-logo.png" alt="BugHound" width="400">
</p>

<h1 align="center">BugHound MCP</h1>

<p align="center"><strong>MCP-Based Security Automation Framework</strong></p>

<p align="center">
  <code>Black Hat Arsenal Asia 2026</code> &nbsp;|&nbsp;
  <code>45 Techniques</code> &nbsp;|&nbsp;
  <code>35 Vuln Classes</code> &nbsp;|&nbsp;
  <code>3 Modes</code>
</p>

---

BugHound is a Model Context Protocol (MCP) server that provides a complete pipeline for web application security reconnaissance and vulnerability assessment. It exposes structured security tools as MCP endpoints, enabling AI clients (Claude, Gemini, Codex) to orchestrate a 7-stage pipeline from target input to verified vulnerability report. BugHound ships with 45 testing techniques -- 29 of which are pure-Python and require zero external tools -- covering injection, access control, server-side, configuration, and data leakage vulnerability classes.

## Features

- **7-Stage Pipeline** -- Init, Enumerate, Discover, Analyze, Test, Validate, Report -- stages collapse based on target type
- **45 Testing Techniques** -- pure-Python fallbacks for every category; no external tools required to start
- **3 Execution Modes** -- MCP Server (for AI clients), CLI (for terminal workflows), AI Agent (autonomous scanning)
- **Professional HTML Reports** -- dark teal dashboard with filtering, export, and executive summary
- **Auth-Aware Testing** -- JWT auto-propagation across all testing techniques
- **Live Reflection Probes** -- real-time XSS reflection detection during discovery
- **Attack Chain Detection** -- multi-step exploitation paths with composite scoring
- **Scope Enforcement** -- mandatory scope validation before any active testing
- **Adaptive Tool Coverage** -- gracefully adapts when external tools are unavailable

## Quick Start

```bash
git clone https://github.com/binderlabs/BugHound-MCP.git
cd BugHound
pip install -r requirements.txt
./scripts/install-tools.sh  # Optional: install Go/external tools

# Mode 1: MCP Server
python -m bughound.server

# Mode 2: CLI
./bhound scan https://target.com
./bhound scan https://target.com -v
./bhound scan https://target.com --profile client   # quick wins only
./bhound recon https://target.com
./bhound list

# Mode 3: AI Agent
./bhound agent https://target.com --provider openrouter --api-key sk-or-...
```

## Installation

### Python Dependencies

```bash
pip install -r requirements.txt
```

Core dependencies: `mcp`, `pydantic`, `aiohttp`, `aiofiles`, `structlog`

Optional (for agent mode): `anthropic`, `openai`

### External Security Tools (Optional)

BugHound works with zero external tools using 29 pure-Python techniques. For full coverage (43 techniques), install the following:

| Tool | Purpose | Install |
|------|---------|---------|
| nuclei | Template-based scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| subfinder | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| gau | URL discovery | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | Archive URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| sqlmap | SQLi validation | `apt install sqlmap` or `pip install sqlmap` |
| dalfox | XSS validation | `go install github.com/hahwul/dalfox/v2@latest` |
| ffuf | Directory fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| arjun | Parameter discovery | `pip install arjun` |
| wafw00f | WAF detection | `pip install wafw00f` |
| playwright | DOM XSS detection (headless browser) | `pip install playwright && playwright install chromium` |
| assetfinder | Subdomain discovery | `go install github.com/tomnomnom/assetfinder@latest` |
| findomain | Subdomain discovery | Download from [GitHub releases](https://github.com/Edu4rdSHL/findomain/releases) |
| gotator | Subdomain permutation | `go install github.com/Josue87/gotator@latest` |
| puredns | DNS resolution | `go install github.com/d3mondev/puredns/v2@latest` |

**Automated install:**

```bash
./scripts/install-tools.sh              # Core + recon + python + seclists (recommended)
./scripts/install-tools.sh --minimal    # Core Go tools only (httpx/nuclei/katana/subfinder/ffuf/dnsx)
./scripts/install-tools.sh --full       # Everything + assetnote wordlists (~1GB download)
```

The installer is idempotent — safe to re-run. Each tool is verified after install; a clear summary at the end shows how many installed/skipped/failed. If any tool fails, the script continues (unlike older versions) and prints diagnostics for the failed tool only.

If your friend (or you) hit "script ran but tools aren't actually installed," re-run `./scripts/install-tools.sh` — the new version explicitly checks `command -v` for every tool after install and reports `[x]` on real failure. No more silent PEP-668 / `set -e` abort issues.

### API Keys for Better Subdomain Coverage (Optional)

BugHound's subdomain enumeration uses `subfinder`, which supports passive data sources via API keys. Without keys, you still get results from free sources (crtsh, HackerTarget, CertSpotter). With keys, you get significantly more subdomains.

Configure in `~/.config/subfinder/provider-config.yaml`:

```yaml
chaos:
  - your-chaos-api-key
virustotal:
  - your-virustotal-api-key
securitytrails:
  - your-securitytrails-api-key
shodan:
  - your-shodan-api-key
censys:
  - your-censys-api-key
```

| Source | Sign up | Free? |
|--------|---------|-------|
| Chaos (ProjectDiscovery) | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io) | Yes |
| VirusTotal | [virustotal.com](https://www.virustotal.com) | Yes |
| SecurityTrails | [securitytrails.com](https://securitytrails.com) | Yes (50 queries/month) |
| Censys | [search.censys.io](https://search.censys.io) | Yes (250 queries/month) |
| Shodan | [shodan.io](https://shodan.io) | Paid ($49 lifetime) |

Chaos also requires an environment variable:

```bash
echo 'export CHAOS_API_KEY="your-key"' >> ~/.zshrc && source ~/.zshrc
```

### BugHound-native API keys (`~/.gau.toml`)

BugHound's own recon modules (chaos subdomain source, GitHub recon, URLScan, AlienVault OTX) read keys from `~/.gau.toml` so they're shared across tools:

```toml
[urlscan]
apikey = "..."

[otx]
apikey = "..."

[chaos]
apikey = "..."

[github]
apikey = "ghp_..."    # read:public_repo is enough
```

Environment variables (`CHAOS_API_KEY`, `PDCP_API_KEY`, `GITHUB_TOKEN`, `GH_TOKEN`) are respected as fallback. GitHub recon and chaos subdomain lookups are skipped silently if no token is found.

## MCP Configuration

### Claude Code

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "bughound": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "bughound.server"],
      "cwd": "/path/to/BugHound",
      "env": {
        "PYTHONPATH": "/path/to/BugHound",
        "BUGHOUND_WORKSPACE_DIR": "/path/to/workspaces"
      }
    }
  }
}
```

Or add via CLI: `claude mcp add --transport stdio --scope project bughound -- python3 -m bughound.server`

### Gemini CLI

Add to `~/.gemini/settings.json` or `.gemini/settings.json` in your project:

```json
{
  "mcpServers": {
    "bughound": {
      "command": "python3",
      "args": ["-m", "bughound.server"],
      "cwd": "/path/to/BugHound",
      "env": {
        "PYTHONPATH": "/path/to/BugHound",
        "BUGHOUND_WORKSPACE_DIR": "/path/to/workspaces"
      },
      "timeout": 600000
    }
  }
}
```

### OpenAI Codex

Add to `~/.codex/config.toml` or `.codex/config.toml` in your project:

```toml
[mcp_servers.bughound]
command = "python3"
args = ["-m", "bughound.server"]
cwd = "/path/to/BugHound"
startup_timeout_sec = 30
tool_timeout_sec = 300

[mcp_servers.bughound.env]
PYTHONPATH = "/path/to/BugHound"
BUGHOUND_WORKSPACE_DIR = "/path/to/workspaces"
```

## MCP Tools Reference

BugHound exposes ~30 MCP tools organized by function (plus 6 agent-mode-only primitives for anti-FP / workflow exploration):

| Tool | Description |
|------|-------------|
| `bughound_init` | Initialize workspace -- classify target, create workspace |
| `bughound_enumerate` | Stage 1: subdomain discovery (subfinder, assetfinder, crtsh, passive APIs) |
| `bughound_enumerate_deep` | Stage 1 deep: active enumeration + DNS bruteforce (background job) |
| `bughound_discover` | Stage 2: full discovery -- probe, crawl, JS analysis, dir scan, param classification |
| `bughound_get_attack_surface` | Stage 3: attack surface analysis with chains, immediate wins, reasoning prompts |
| `bughound_submit_scan_plan` | Submit testing strategy (targets + test classes) |
| `bughound_execute_tests` | Stage 4: run all techniques based on scan plan (background job) |
| `bughound_test_single` | Surgical test on one endpoint with one technique |
| `bughound_nuclei_scan` | Direct nuclei scan with custom options |
| `bughound_list_techniques` | List all 48 techniques with availability (optional `test_profile` filter) |
| `bughound_list_pipelines` | List 17 one-liner pipelines |
| `bughound_run_pipeline` | Run a one-liner pipeline (gf + qsreplace + kxss etc.) |
| `bughound_validate_all` | Stage 5: batch validate all findings (background job) |
| `bughound_validate_finding` | Validate one specific finding |
| `bughound_validate_immediate_wins` | Validate Stage 3 immediate wins |
| `bughound_generate_report` | Stage 6: generate HTML + markdown reports |
| `bughound_analyze_host` | Deep-dive analysis of a specific host |
| `bughound_enrich_target` | Intelligence dossier on a host |
| `bughound_get_immediate_wins` | Get findings ready to report without testing |
| `bughound_scope_check` | Verify target is in scope |
| `bughound_check_tool_coverage` | Check installed security tools |
| `bughound_workspace_list` | List all workspaces |
| `bughound_workspace_get` | Get workspace details |
| `bughound_workspace_results` | View workspace results dashboard |
| `bughound_workspace_delete` | Delete a workspace |
| `bughound_job_status` | Check background job progress |
| `bughound_job_results` | Get completed job results |
| `bughound_job_cancel` | Cancel a running job |

## Usage Prompts for AI Clients

When using BugHound through an AI client (Claude, Gemini, Codex), use natural language prompts:

**Basic scan:**
```
Scan https://target.com for vulnerabilities using BugHound
```

**Step by step:**
```
1. Initialize BugHound for https://target.com
2. Run discovery
3. Show me the attack surface
4. Create a scan plan focused on SQLi and XSS
5. Execute the tests
6. Validate the findings
7. Generate a report
```

**Quick recon:**
```
Run BugHound recon on example.com and show me what you find
```

**Targeted test:**
```
Test https://target.com/api/search?q=test for SQL injection using BugHound
```

## CLI Reference

```
./bhound scan <target>                       # Full pipeline (Stages 0-6)
./bhound scan <target> -v                    # Verbose mode (show all activity)
./bhound scan <target> --depth deep          # Deep scan
./bhound scan <target> --profile client      # Client-side bugs only (XSS, CORS, redirect, CSP)
./bhound scan <target> --profile server      # Server-side bugs only (SQLi, SSRF, RCE, LFI, XXE, auth)
./bhound scan <target> --profile both        # Full coverage (default; also prompts interactively if omitted)
./bhound scan <target> --skip-validate       # Skip validation stage
./bhound scan <target> --skip-nuclei         # Skip nuclei scanning
./bhound scan <target> --resume <ws_id>      # Resume crashed scan
./bhound scan <target> --output json         # JSON output for CI/CD
./bhound scan <target> --max-hosts 5         # Auto-select top 5 hosts (broad domains)
./bhound scan <target> --no-color            # No terminal colors
./bhound scan <target> -q                    # Quiet mode (summary only)
./bhound recon <target>                      # Discovery only (Stages 0-2)
./bhound recon <target> --max-hosts 3        # Recon top 3 hosts only
./bhound analyze <workspace_id>              # Attack surface analysis
./bhound test <workspace_id>                 # Run tests on existing recon
./bhound test <workspace_id> --profile client  # Test only client-side classes
./bhound validate <workspace_id>             # Validate findings
./bhound report <workspace_id>               # Generate reports
./bhound list                                # List workspaces
./bhound agent <target> --provider ...       # AI agent mode
./bhound agent <target> --profile server     # Agent mode restricted to server-side tests
./bhound serve                               # Start MCP server
```

### Test Profiles

Split testing between browser-side and server-side bugs to reduce scan time:

| Profile | Classes | Use when |
|---|---|---|
| `client` | XSS (all variants), open redirect, CORS, CSTI, prototype pollution, CSP/security headers, clickjacking | Quick wins, bug bounty triage, production-safe scans |
| `server` | SQLi, SSRF, RCE, LFI, XXE, SSTI, IDOR, BAC, JWT, deserialization, auth bypass, CMS, rate limiting | Deep auth/injection work, slower but covers blind/time-based bugs |
| `both` | Everything (default) | Full assessment |

Stages 0-3 (recon + attack surface) always run identically — the profile only filters what Stage 4 tests. Hybrid checks (nuclei, vulnerable components, security headers) run in every profile.

When invoked from MCP:

```
bughound_execute_tests(workspace_id, test_profile="client")
bughound_list_techniques(test_profile="server")
# or inside the scan plan:
bughound_submit_scan_plan(workspace_id, {
  "targets": [...],
  "global_settings": {"test_profile": "client"}
})
```

### Speed Modes

Tune concurrency for the target's WAF profile:

| Mode | Flag | Use when |
|---|---|---|
| `stealth` | `--stealth` | Real bug-bounty targets behind Cloudflare/Akamai — clamps nuclei rate ≤10, per-technique concurrency 5, low parallelism |
| `normal` | (default) | Most targets — balanced: nuclei rate 100, per-technique concurrency 15 |
| `fast` | `--fast` | Lab targets / owned infra — cranks nuclei rate 250+, per-technique concurrency 30, 4 heavy slots |

Works on `scan`, `test`, and `agent` commands. Mutually exclusive with each other. Combine freely with `--profile`:

```
./bhound scan <target> --profile client --fast     # 5-10× faster than default on labs
./bhound scan <target> --stealth                    # slow + safe for bounty
./bhound agent <target> --profile server --stealth  # AI agent, server-only, stealth rate
```

### Extended Recon Sources

Stage 2 discovery now includes additional passive/active sources beyond subfinder + gau:

- **Chaos dataset** (ProjectDiscovery) — curated BB subdomain corpus. Free tier. Needs `[chaos]` key.
- **GitHub recon** — searches GitHub code for `"<domain>" extension:env`, `password`, `api_key`, etc. Extracts secrets from result snippets with inline regex. Optional deep mode clones org repos and runs trufflehog. Needs `[github]` token.
- **Cloud bucket discovery** — S3 / Azure Blob / GCS / DO Spaces permutation + probing. Generates bucket-name candidates from domain + discovered subdomains. Reports publicly-listable buckets as HIGH severity.
- **Expanded sensitive-path probe** — 172 paths covering env variants (`.env.dev`, `.env.staging`), framework configs (`appsettings.json`, `application.yml`), credentials (`.aws/credentials`, `.ssh/id_rsa`), git/svn exposure, backup patterns (`backup.7z`, `database.sql.gz`), Spring Actuator, Next.js leaks, CI/CD artifacts (`Jenkinsfile`, `.gitlab-ci.yml`).
- **Tiered wordlist selection** — auto-picks assetnote/SecLists raft-medium for `--depth light`, raft-large for `--depth deep`. Falls back to dirbuster-medium (86k) when SecLists isn't installed.

### SPA (Single Page Application) handling

Modern webapps ship an empty HTML skeleton like:

```html
<body><div id="root"></div><script src="/assets/index-X.js"></script></body>
```

Traditional crawlers see nothing — zero forms, zero links, zero content. Stage 2 now detects this and pivots:

1. **SPA detection** — recognizes React / Vue / Angular / Next / Vite / CRA / Nuxt / Gatsby / Remix / Svelte-Kit skeletons via body emptiness + script patterns + framework signatures.
2. **Router config extraction** — parses React Router / Vue Router / Angular Router definitions from the downloaded JS bundle, surfacing routes like `/users/:id`, `/admin/dashboard` that static crawling would miss.
3. **GraphQL operation extraction** — grabs `gql\`query ... \`` / `mutation ...` operation names from the bundle.
4. **Common backend probe** — tries 30+ typical SPA API paths (`/api/health`, `/api/me`, `/graphql`, `/graphiql`, `/api/config`, `/.well-known/openid-configuration`, `/actuator/*`, etc.) with content-type + body-signal filtering to dodge SPA fallback 200s.

Results feed into `all_urls`, so downstream phases (param discovery, nuclei, testing) see the real attack surface. Outputs land in:

- `hosts/spa_detection.json` — which hosts are SPAs + framework + confidence
- `urls/spa_routes.json` — extracted client-side routes
- `urls/spa_backends.json` — discovered backend endpoints
- `urls/graphql_operations.json` — GraphQL operation names

### Agent Mode Advanced Primitives

`./bhound agent` now ships with anti-FP and workflow-exploration tools the AI can call:

| Tool | Purpose |
|---|---|
| `verify_not_honeytoken` | Replays URL with safe vs injection payload; kills FPs where the "vuln" is a static mock response (common on intentionally-vulnerable labs). Use before confirming SQLi/LFI/RCE/SSTI. |
| `detect_url_auth` | Flags auth-in-URL anti-pattern (`?UserName=`, `?token=`) — HIGH severity, credentials leak via history/referrer/logs. |
| `test_viewstate_binding` | ASP.NET WebForms — captures `__VIEWSTATE` in one session, replays in another. If accepted → CSRF token replay possible. |
| `capture_workflow` | Playwright browser + network recording. Executes sequence of click/input/navigate actions, returns all captured requests (method, URL, post body including hidden `__VIEWSTATE`/CSRF tokens, Set-Cookie). Essential for understanding multi-step flows. |
| `submit_form` | Parses form, preserves hidden fields, submits with overrides. Returns full round-trip including session-cookie detection and URL-auth-in-redirect flagging. |
| `record_user_story` | Persists structured exploration results (personas, routes, APIs with payloads, notes, follow-up candidates) to `workspace/<id>/agent/user_stories.json`. |

For broad domain targets (e.g., `*.example.com`), BugHound enumerates subdomains and probes them with httpx. In CLI mode, you are prompted to select which live hosts to scan:

```
Found 9 live hosts:
  1. [200] https://blog.example.com [WordPress]
  2. [200] https://mail.example.com Login form
  3. [200] https://api.example.com [Express, Node.js]
  4. [403] https://cdn.example.com [CloudFront]
  ...

Options:
  3      -- scan only host #3
  1,3,5  -- scan specific hosts
  1-10   -- scan hosts 1 through 10
  all    -- scan all 9 hosts

Select [all]: 1,2,3
Selected 3 host(s) -- continuing scan
```

Use `--max-hosts N` to skip the prompt and auto-select the top N hosts.

## AI Agent Mode

BugHound's agent mode combines **CLI scanning speed** with **AI validation depth**. It runs all 45 automated techniques first, then an AI with 6 specialist experts validates every finding individually -- sending targeted payloads, reading pages, confirming or rejecting each one. No finding goes unverified.

**Hybrid approach:** CLI breadth + AI depth
```
Phase 1: Automated Recon (Stages 0-3)     → discover attack surface
Phase 2: Automated Testing (45 techniques) → find vulnerabilities fast
Phase 3: AI Validation + Discovery         → verify each finding, reject false positives
Phase 4: Report Generation                 → professional deliverables
```

**6 specialist experts:** SQLi (5 DB extraction playbooks), XSS (6 injection contexts), LFI (config file priority lists), SSRF (cloud metadata + bypasses), RCE (per-language eval), Auth (login bypass + JWT).

**12 AI tools:** `read_page`, `browse_page` (Playwright), `run_tool` (Kali tools), `http_request`, `extract_sqli_data`, `read_file_via_lfi`, `update_finding_status`, `add_finding`, `get_findings`, `get_attack_surface`, `validate_findings`, `generate_report`

```bash
# Using OpenRouter (access to all models)
./bhound agent https://target.com --provider openrouter --model openai/gpt-5.4-mini

# Using .env file for API key
echo "OPENROUTER_API_KEY=sk-or-..." > .env
./bhound agent https://target.com --provider openrouter

# Supported providers
--provider anthropic    # Claude (native SDK)
--provider openai       # GPT-4o
--provider grok         # Grok-3 (xAI)
--provider openrouter   # Any model via OpenRouter
```

**What AI adds beyond CLI:**
```
CLI scan:    36 findings, all PENDING — needs human review
Agent mode:  36 findings → 22 CONFIRMED, 12 FALSE POSITIVE, 2 MANUAL REVIEW
             AI sent 27 http_requests to verify each finding individually
```

## Pipeline Architecture

```
Stage 0: Init        -->  Target classification + workspace
Stage 1: Enumerate   -->  Subdomain discovery (skipped for single hosts)
Stage 2: Discover    -->  Probe, crawl, JS analysis, dir scan, param classification
Stage 3: Analyze     -->  Attack surface, chains, immediate wins, scan plan
Stage 4: Test        -->  45 techniques in parallel (nuclei + pure-Python)
Stage 5: Validate    -->  Surgical verification (sqlmap, dalfox, curl)
Stage 6: Report      -->  HTML dashboard, bug bounty MD, executive summary
```

Stages collapse based on target type:
- **Broad domain** (`*.example.com`): all stages run
- **Single host** (`dev.example.com`): Stage 1 skipped, Stage 2 starts at probing
- **Single endpoint** (`https://dev.example.com/api`): Stage 1 skipped, Stage 2 crawls from path only
- **URL list**: Stage 1 skipped, batch probe and crawl

## Techniques (45 Total)

**Injection**
- SQLi (error-based, blind, time-based), XSS (reflected, stored, DOM), SSTI, CSTI, CRLF, header injection

**File Access**
- LFI, XXE, path traversal

**Server-Side**
- SSRF, RCE (command injection, eval), prototype pollution

**Access Control**
- IDOR, path IDOR, broken access control, mass assignment

**Configuration**
- Security headers, version disclosure, transport security, ViewState MAC, default credentials

**Data Leaks**
- Sensitive field leakage, PII in HTML, vulnerable components

**Authentication**
- Cookie injection (SQLi, XSS, deserialization), JWT analysis, rate limiting

**External**
- Nuclei templates, WordPress, Spring actuator, GraphQL (introspection + data leaks), CORS

## Project Structure

```
BugHound/
├── CLAUDE.md                  # Project instructions
├── PLAN.md                    # Development plan
├── DEVLOG.md                  # Development journal
├── README.md
├── bughound/
│   ├── server.py              # MCP server entry point
│   ├── config/
│   │   └── settings.py        # Configuration
│   ├── core/
│   │   ├── target_classifier.py   # Stage 0: target type detection
│   │   ├── workspace.py           # Workspace CRUD + lazy dir creation
│   │   ├── job_manager.py         # Async job lifecycle
│   │   └── tool_runner.py         # Unified subprocess runner
│   ├── stages/
│   │   ├── enumerate.py       # Stage 1
│   │   ├── discover.py        # Stage 2
│   │   ├── analyze.py         # Stage 3
│   │   ├── test.py            # Stage 4
│   │   ├── validate.py        # Stage 5
│   │   └── report.py          # Stage 6
│   ├── tools/
│   │   ├── base.py            # Unified base tool
│   │   ├── recon/             # subfinder, httpx, crtsh, etc.
│   │   ├── scanning/          # nuclei, ffuf, dalfox, sqlmap, etc.
│   │   ├── discovery/         # gospider, jsluice, arjun, etc.
│   │   ├── testing/           # injection_tester, graphql, jwt testers
│   │   └── oneliners/         # qsreplace, kxss, gf, uro, unfurl, anew + pipeline engine
│   ├── schemas/
│   │   └── models.py          # Pydantic models
│   └── utils/
│       └── helpers.py
├── tests/
├── scripts/
│   └── install-tools.sh       # Security tools installer
└── workspaces/                # Runtime data (gitignored)
```

## Black Hat Arsenal

BugHound is featured at **Black Hat Arsenal Asia 2026**.

- **Date:** April 24, 2026
- **Track:** Web AppSec
- **Location:** Arsenal Station 2, Business Hall
- **Event:** [Black Hat Asia 2026](https://www.blackhat.com/asia-26/)

## License

MIT License

## Credits

Built by **Krishna Naidu**, **eric tee**, **Lwin Min Oo**, **Kai-Wei Hoon**, **Valen Sai**
