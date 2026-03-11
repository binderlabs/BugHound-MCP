# BugHound Intelligence Layer

## Why This Exists

Every recon framework runs the same checklist on every target. BugHound is different because the AI client reasons between every step. This document defines exactly what "intelligence" means at each stage and how the MCP server enables it.

---

## Intelligence at Each Stage

### Stage 1: Pattern-Aware Enumeration

The MCP server doesn't just return a flat list of subdomains. It returns structured intelligence.

**What the MCP returns:**

```
{
  "subdomains_count": 247,
  "naming_patterns": [
    {"pattern": "dev-*", "count": 12, "examples": ["dev-api", "dev-auth", "dev-payments"]},
    {"pattern": "api-v*", "count": 4, "examples": ["api-v1", "api-v2", "api-v3"]},
    {"pattern": "*-staging", "count": 8}
  ],
  "ip_clusters": [
    {"ip_range": "104.26.x.x", "count": 180, "provider": "Cloudflare", "note": "CDN-protected"},
    {"ip_range": "52.14.x.x", "count": 3, "provider": "AWS", "note": "NOT behind CDN - direct exposure"}
  ],
  "anomalies": [
    "3 subdomains resolve to non-CDN IPs while rest are behind Cloudflare",
    "internal-api.example.com uses unusual TLD pattern, may be misconfigured DNS",
    "6 subdomains have wildcard CNAME to defunct Heroku app - takeover candidates"
  ],
  "dns_interesting": [
    "SPF record includes 3 third-party email services",
    "DMARC policy is 'none' - email spoofing possible",
    "TXT record leaks internal subnet: 10.0.42.0/24"
  ]
}
```

**What the AI does with it:**

"I see 12 dev-* subdomains. This company has dev environments exposed to the internet. These often have weaker security controls. Prioritize dev-* hosts in discovery."

"180 of 247 subdomains are behind Cloudflare, but 3 are on raw AWS IPs. Those 3 are likely backend services exposed without WAF protection. Test those first."

"6 Heroku-pointed subdomains are takeover candidates. Quick wins before deep recon."

---

### Stage 2: Context-Rich Discovery

The MCP returns discovery data with cross-references and flags.

**What the MCP returns for hosts:**

```
{
  "host": "api.example.com",
  "status_code": 200,
  "technologies": ["Node.js", "Express", "GraphQL"],
  "waf": null,
  "cdn": null,
  "ip": "52.14.23.101",
  "security_headers": {
    "present": ["X-Frame-Options"],
    "missing": ["CSP", "HSTS", "X-Content-Type-Options", "Strict-Transport-Security"],
    "score": "F"
  },
  "flags": [
    "NO_WAF: Direct exposure, no WAF detected",
    "MISSING_HEADERS: 4 critical security headers missing",
    "NON_CDN_IP: Not behind CDN while siblings are",
    "GRAPHQL: GraphQL detected - check introspection"
  ],
  "urls_discovered": 45,
  "parameters_found": 15,
  "js_secrets": [
    {"type": "AWS_ACCESS_KEY", "file": "/static/js/app.min.js", "line": 4521},
    {"type": "API_ENDPOINT", "value": "/api/internal/admin", "file": "/static/js/app.min.js"}
  ],
  "related_findings": [
    "This IP (52.14.23.101) also hosts staging-api.example.com",
    "JS references /api/internal/admin which was NOT found in crawl results - hidden endpoint"
  ]
}
```

**What the AI does with it:**

"api.example.com is a goldmine. No WAF, no CDN, missing all security headers, GraphQL with potential introspection, leaked AWS key in JS, AND a hidden /api/internal/admin endpoint found only in JavaScript. This is my #1 target."

---

### Stage 3: Correlation Engine

The attack surface summary pre-computes cross-stage correlations the AI can reason about.

**Correlation types the MCP should surface:**

```
{
  "cross_references": [
    {
      "type": "HIDDEN_ENDPOINT",
      "description": "/api/internal/admin found in JS but not in crawl results",
      "source": "jsluice analysis of /static/js/app.min.js",
      "significance": "Endpoint exists but is not linked publicly - likely admin/internal access",
      "affected_host": "api.example.com"
    },
    {
      "type": "SHARED_INFRASTRUCTURE",
      "description": "api.example.com and staging-api.example.com share IP 52.14.23.101",
      "significance": "Staging may have weaker controls, same server",
      "affected_hosts": ["api.example.com", "staging-api.example.com"]
    },
    {
      "type": "LEAKED_CREDENTIAL",
      "description": "AWS_ACCESS_KEY found in JS, same key pattern seen in 2 other JS files",
      "significance": "Key may be valid and grant access to AWS resources",
      "affected_hosts": ["api.example.com", "app.example.com"]
    },
    {
      "type": "VERSION_GAP",
      "description": "api-v1 and api-v2 exist, api-v3 returns 404 but DNS resolves",
      "significance": "v3 may be in development/staging, potentially less hardened",
      "affected_hosts": ["api-v3.example.com"]
    },
    {
      "type": "TECH_MISMATCH",
      "description": "blog.example.com runs WordPress 6.3 but all other hosts are Node.js/React",
      "significance": "Different tech stack = different team = potentially different security posture",
      "affected_hosts": ["blog.example.com"]
    },
    {
      "type": "TAKEOVER_READY",
      "description": "old-shop.example.com CNAME points to shopify but returns NXDOMAIN",
      "significance": "Immediate subdomain takeover possible",
      "affected_hosts": ["old-shop.example.com"]
    }
  ]
}
```

**What the AI does with it:**

The AI reads these correlations and builds a prioritized, intelligent scan plan that no bash script could produce. It doesn't just say "test everything." It says "test the hidden admin endpoint first, verify the AWS key, check the staging server for weaker controls, claim the takeover, then do broad scanning."

---

## Intelligence Implementation Guide

### How to Build Pattern Detection (Stage 1)

In `stages/enumerate.py`, after deduplication:

1. Extract subdomain prefixes and suffixes
2. Group by common patterns (dev-, staging-, api-, test-, v1-, v2-)
3. Group resolved IPs by /24 subnet
4. Cross-reference IP ranges with known CDN/cloud provider ranges
5. Flag subdomains that don't match the majority pattern (anomalies)
6. Parse DNS TXT records for leaked internal info

This is simple string processing and IP comparison. No AI needed. Just structured output.

### How to Build Cross-Reference Detection (Stage 2-3)

In `stages/analyze.py`, when building the attack surface summary:

1. Compare JS-discovered endpoints against crawled URLs. Any endpoint in JS but not crawled = HIDDEN_ENDPOINT
2. Group hosts by IP address. Shared IP = SHARED_INFRASTRUCTURE
3. Collect all secrets across all JS files. Same key in multiple files = widespread leak
4. Look for version patterns (v1, v2, v3) and check if gaps exist
5. Compare technology stacks across hosts. Outliers = TECH_MISMATCH
6. Check all CNAME records against known takeover fingerprints

Again, this is deterministic logic. Pattern matching, set operations, string comparison. The AI interprets the results. The MCP just surfaces them.

### How to Build Flags (Stage 2)

In the httpx/discovery processing:

1. NO_WAF: wafw00f returns no WAF detected
2. MISSING_HEADERS: security header audit shows critical gaps
3. NON_CDN_IP: this host's IP doesn't match the CDN range that most hosts use
4. GRAPHQL: response contains /graphql or introspection indicators
5. OLD_TECH: detected technology version has known CVEs
6. OPEN_CORS: CORS headers allow wildcard or reflected origin
7. DEBUG_MODE: response contains stack traces, debug headers, or verbose errors
8. DEFAULT_PAGE: response matches known default pages (Apache, nginx, IIS, etc.)

Each flag is a boolean check. Simple. But together they tell a story the AI can read.

---

## What This Means for Arsenal Demo

The demo flow should highlight intelligence, not tools:

1. "Let me scan example.com" - basic entry
2. AI reads enumeration results: "I notice 3 hosts aren't behind your CDN. And I see a pattern of dev- subdomains exposed to the internet. Let me focus discovery there."
3. AI reads discovery results: "I found a hidden API endpoint in your JavaScript that isn't linked from anywhere public. And there's an AWS key leaked in the same JS file."
4. AI builds scan plan: "Based on what I found, here's my testing strategy..." (shows reasoning)
5. AI validates findings: "Confirmed SQL injection on the hidden endpoint. Here's the proof."
6. AI generates report: ready for submission

The audience sees the AI thinking like a pentester. That's the value. That's what no other tool does.
