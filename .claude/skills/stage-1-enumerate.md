# Stage 1: Enumerate

## Purpose

Answers "what targets exist?" Subdomain discovery and DNS record collection. Only runs for BROAD_DOMAIN target types. Completely skipped for SINGLE_HOST, SINGLE_ENDPOINT, and URL_LIST.

## Scope-Aware Behavior

When target is BROAD_DOMAIN:
- Light: passive sources only (subfinder, assetfinder, findomain, crt.sh). Should finish in 30-60 seconds.
- Deep: passive + active bruteforce (puredns with large wordlist) + permutation fuzzing (gotator/dnsgen). Runs as async background job. 5-15+ minutes.

When target is anything else:
- Return immediately with the provided target(s) as the "enumerated" list. No tools invoked.

## Tool Chain

### Passive Subdomain Discovery (Light + Deep)
- subfinder: primary passive enumerator, multiple API sources
- assetfinder: secondary passive source
- findomain: additional passive source  
- crt.sh: certificate transparency logs (API-based, no binary needed)
- Run all in parallel, deduplicate results

### Active Enumeration (Deep only)
- puredns / massdns: bruteforce with large wordlists (2M+ entries)
- gotator / dnsgen: permutation generation from discovered subdomains
- Recursive: run passive enum on newly discovered subdomains

### DNS Resolution
- Resolve all discovered subdomains to A/AAAA records
- Collect full DNS records: A, AAAA, CNAME, MX, TXT, NS, SOA
- Detect wildcard DNS (if *.example.com resolves, mark it)
- Parse SPF/DKIM/DMARC from TXT records

## Output

Written to workspace:
- subdomains/all.txt: deduplicated subdomain list (one per line)
- subdomains/sources.json: which tool found which subdomain (for provenance)
- dns/records.json: full DNS records per subdomain
- dns/wildcards.json: detected wildcard domains

All output validated against Pydantic schemas before writing.

## MCP Tools

### bughound_enumerate (synchronous, light mode)
- Input: workspace_id
- Reads: workspace config for target and depth
- Process: run passive tools in parallel, resolve DNS, deduplicate
- Output: subdomain count, key stats, data written to workspace
- Timeout: 120 seconds max

### bughound_enumerate_deep (asynchronous, deep mode)
- Input: workspace_id
- Process: starts background job for full enumeration pipeline
- Output: job_id (poll with bughound_job_status)
- Background job writes progressive results as each tool completes

## Key Design Notes

- Deduplication happens at this stage. Downstream stages always read from subdomains/all.txt which is already clean.
- Source tracking in sources.json is valuable for debugging ("why did we miss this subdomain?" -> "no tool found it passively, needed bruteforce")
- Wildcard detection is critical. If *.example.com resolves, hundreds of fake subdomains will appear. Mark these and let Stage 2 handle them carefully.
- If zero subdomains are found after passive enum in light mode, suggest the user run deep mode. Don't auto-escalate.
