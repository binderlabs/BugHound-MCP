# Stage 2: Discover

## Purpose

Answers "what's running on these targets?" Full attack surface mapping. Probes live hosts, fingerprints technology, crawls for URLs, extracts JS endpoints, harvests parameters, discovers secrets, enumerates cloud assets.

This is the largest and most important stage. For SINGLE_HOST targets, this is where the pipeline effectively starts.

## Module Breakdown

### 2A: Probe + Fingerprint
- httpx: probe all subdomains/targets for HTTP/HTTPS response. Collect status code, page title, content length, server header, redirect chain, technology fingerprint.
- wafw00f: WAF/CDN detection and identification
- SSL/TLS certificate analysis: SANs, org, expiry, issuer (can extract from httpx or dedicated tool)
- Security headers audit: CSP, HSTS, X-Frame-Options, CORS, etc.

Probing acts as a natural filter. Dead hosts, parked domains (generic parking page), redirect-only hosts get tagged and deprioritized. This is the first decision pass (noise removal) without needing a separate decision stage.

### 2B: Crawl + URL Discovery
- gospider / hakrawler / katana: crawl live hosts for URLs
- gau + waybackurls: historical URL scraping from Wayback Machine, CommonCrawl, OTX
- robots.txt + sitemap.xml parsing
- Light depth: crawl depth 2, small timeout
- Deep depth: crawl depth 5, longer timeout, form discovery

### 2C: JavaScript Analysis
- jsluice / linkfinder: extract endpoints, paths, and API routes from JS files
- JS file enumeration from crawl results
- Source map detection (.js.map files)
- Secret extraction from JS (API keys, tokens, hardcoded credentials)

### 2D: Parameter Harvesting
- Extract parameters from historical URLs (gau/waybackurls output)
- arjun: active parameter discovery on interesting endpoints
- Collect unique parameter names per endpoint for Stage 4 testing

### 2E: Directory Fuzzing
- ffuf / feroxbuster: directory and file brute-forcing on live hosts
- Light: common.txt wordlist (~4k entries), quick pass
- Deep: raft-large or similar (~100k entries), recursive
- Only run on hosts that passed the probe filter (no point fuzzing dead hosts)

### 2F: Cloud + Takeover
- Cloud provider identification from IPs/CNAMEs (AWS, Azure, GCP)
- S3 / Azure Blob / GCP bucket enumeration
- Subdomain takeover detection: check dangling CNAMEs pointing to deprovisioned services (GitHub Pages, Heroku, S3, etc.)

## Execution Order

The modules have dependencies:
1. 2A (Probe) runs first. Its output (live hosts list) feeds everything else.
2. 2B (Crawl) and 2E (Dirfuzz) can run in parallel on live hosts.
3. 2C (JS Analysis) depends on 2B output (needs discovered JS file URLs).
4. 2D (Parameter Harvest) depends on 2B output (needs discovered URLs).
5. 2F (Cloud/Takeover) can run in parallel with everything after 2A.

For SINGLE_HOST: all modules run on one target. Should complete in 2-5 minutes for light.
For BROAD_DOMAIN: runs as async job. Each module iterates over all live hosts.
For SINGLE_ENDPOINT: only 2B (crawl from that path) + 2C + 2D run.

## Output

Written to workspace:
- hosts/live_hosts.json: all live hosts with full fingerprint data
- hosts/technologies.json: tech stack per host
- hosts/waf.json: WAF/CDN detection results
- hosts/security_headers.json: header audit per host
- urls/crawled.json: all discovered URLs with source attribution
- urls/parameters.json: unique parameters per endpoint
- urls/js_files.json: discovered JavaScript files
- endpoints/api_endpoints.json: extracted API routes from JS
- secrets/js_secrets.json: extracted secrets from JS (keys, tokens)
- cloud/providers.json: cloud provider identification
- cloud/buckets.json: discovered cloud storage
- cloud/takeover_candidates.json: potential subdomain takeovers
- dirfuzz/{hostname}.json: directory fuzzing results per host

## MCP Tools

### bughound_discover
- Input: workspace_id
- Reads: enumeration results (or single target from init)
- For SINGLE_HOST: runs synchronously, returns results directly
- For BROAD_DOMAIN: starts async job, returns job_id
- Output: attack surface summary + data written to workspace

## Key Design Notes

- This stage produces the attack surface map that Stage 3 (Analyze) consumes. The richer the data here, the better the AI's decisions in Stage 3.
- For the 10-day sprint, prioritize: httpx probe (2A) + gau/waybackurls (2B) + JS analysis (2C). These give the most value with least effort. Dirfuzz (2E) and cloud enum (2F) are nice-to-have.
- Crawling (gospider) is high value but can be slow. Set aggressive timeouts per host.
- Secret extraction from JS is a crowd-pleaser for demos. Prioritize this.
