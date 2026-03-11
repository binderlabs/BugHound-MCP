# Workspace Schema

## Directory Structure

Data-type-based organization. NO light/deep split. Depth metadata lives inside the data, not in the folder hierarchy.

```
workspaces/{target_sanitized}_{short_uuid}/
├── metadata.json              # System-managed execution state
├── config.json                # User-managed preferences
├── scan_plan.json             # Stage 3 output, Stage 4 input
│
├── subdomains/                # All subdomain data
│   ├── all.txt                # Deduplicated master list
│   └── sources.json           # Which tool found which subdomain
│
├── dns/                       # All DNS data
│   ├── records.json           # A, AAAA, CNAME, MX, TXT, NS, SOA per subdomain
│   └── wildcards.json         # Detected wildcard domains
│
├── hosts/                     # All host data
│   ├── live_hosts.json        # httpx results: status, title, server, tech, CDN
│   ├── technologies.json      # Tech stack per host
│   ├── waf.json               # WAF/CDN detection per host
│   ├── security_headers.json  # Header audit per host
│   └── screenshots/           # Visual recon (lazily created)
│
├── urls/                      # All URL/endpoint data
│   ├── crawled.json           # Crawled URLs with source attribution
│   ├── parameters.json        # Unique parameters per endpoint
│   └── js_files.json          # Discovered JavaScript files
│
├── endpoints/                 # Extracted API/route data
│   └── api_endpoints.json     # Routes from JS analysis
│
├── secrets/                   # Extracted secrets
│   └── js_secrets.json        # API keys, tokens from JS
│
├── cloud/                     # Cloud asset data
│   ├── providers.json         # Cloud provider identification
│   ├── buckets.json           # S3/Azure/GCP storage
│   └── takeover_candidates.json
│
├── dirfuzz/                   # Directory fuzzing results
│   └── {hostname}.json        # Per-host results
│
├── vulnerabilities/           # Stage 4 + 5 output
│   ├── scan_results.json      # Raw Stage 4 findings
│   ├── validated.json         # Stage 5 results (confirmed/rejected)
│   ├── confirmed/             # One JSON per confirmed finding with evidence
│   ├── false_positives.json   # Dismissed findings
│   └── manual_review.json     # Needs human review
│
├── reports/                   # Stage 6 output
│   ├── bug_bounty_report.md
│   ├── technical_report.md
│   ├── executive_summary.md
│   └── evidence/              # Supporting files
│
└── jobs/                      # Job tracking
    └── {job_id}.json          # One file per background job
```

## Lazy Directory Creation

Directories are NOT created upfront when workspace is initialized. They are created on-demand when a tool first writes to them. This keeps the workspace clean and reflects what actually ran.

metadata.json defines the full schema of what CAN exist. The filesystem shows what DID happen.

## metadata.json Schema

```json
{
  "workspace_id": "example_com_a1b2c3d4",
  "target": "example.com",
  "target_type": "BROAD_DOMAIN",
  "classification": {
    "type": "BROAD_DOMAIN",
    "normalized_targets": ["example.com"],
    "stages_to_run": [0, 1, 2, 3, 4, 5, 6]
  },
  "depth": "light",
  "created_at": "2026-03-11T10:00:00Z",
  "updated_at": "2026-03-11T10:15:00Z",
  "current_stage": 2,
  "stage_history": [
    {"stage": 0, "status": "completed", "started_at": "...", "completed_at": "..."},
    {"stage": 1, "status": "completed", "started_at": "...", "completed_at": "..."},
    {"stage": 2, "status": "running", "started_at": "..."}
  ],
  "stats": {
    "subdomains_found": 247,
    "live_hosts": 89,
    "urls_discovered": 4521,
    "findings_total": 12,
    "findings_confirmed": 5
  },
  "tool_versions": {
    "subfinder": "2.6.3",
    "httpx": "1.3.7",
    "nuclei": "3.1.0"
  }
}
```

## config.json Schema

```json
{
  "scope": {
    "include": ["*.example.com"],
    "exclude": ["staging.example.com", "*.internal.example.com"]
  },
  "depth": "light",
  "api_keys": {
    "shodan": "${SHODAN_API_KEY}",
    "securitytrails": "${SECURITYTRAILS_API_KEY}"
  },
  "tool_overrides": {
    "subfinder_threads": 50,
    "httpx_threads": 100,
    "ffuf_wordlist": "/path/to/custom/wordlist.txt"
  },
  "timeouts": {
    "passive_recon": 60,
    "active_recon": 300,
    "crawl_per_host": 300,
    "dirfuzz_per_host": 600,
    "nuclei": 600
  }
}
```

## Data Format Conventions

### Text files (.txt)
- One entry per line
- No headers, no comments
- UTF-8 encoded
- Deduplicated (no duplicate lines)
- Sorted alphabetically

### JSON files (.json)
- All JSON validated against Pydantic models before writing
- Pretty-printed with 2-space indent (human-readable)
- UTF-8 encoded
- Top-level structure is always an object (not array) with metadata:

```json
{
  "generated_at": "2026-03-11T10:00:00Z",
  "generated_by": "subfinder",
  "target": "example.com",
  "count": 247,
  "data": [ ... ]
}
```

### Per-host files (dirfuzz, screenshots)
- Filename: sanitized hostname (dots replaced with underscores)
- Example: api_example_com.json

## Idempotency

When a tool runs again on the same workspace:
- Append new findings, deduplicate, overwrite the file
- The sources.json tracks which run found what
- Job history in metadata.json tracks all executions
- No versioning of individual data files (keep it simple)

## Workspace States

- INITIALIZED: workspace created, no scans run
- ENUMERATING: Stage 1 in progress
- DISCOVERING: Stage 2 in progress
- ANALYZING: Stage 3 (waiting for AI scan plan)
- TESTING: Stage 4 in progress
- VALIDATING: Stage 5 in progress
- COMPLETED: all stages done, reports generated
- ARCHIVED: workspace archived (read-only)

State tracked in metadata.json current_stage + stage_history.
