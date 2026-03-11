# Stage 3: Analyze (Decision Engine)

## Purpose

Reads the full attack surface from Stage 2 and presents it as structured data for the AI client to reason about. The AI client IS the decision engine. This stage formats data for AI consumption and accepts the AI's scan plan back.

## Critical Design Principle

NO AI calls inside the MCP server. The MCP server does NOT score targets, does NOT prioritize, does NOT decide what to test. It provides the data. The AI client (Claude, Gemini) reads the attack surface summary, thinks about what's interesting, and tells the MCP server what to test via a scan plan.

This is what makes BugHound different from every other recon framework. The intelligence is in the AI, not in hardcoded scoring algorithms.

## Two Decision Points

### Decision Point 1: After Stage 1 (Enumeration)
- Automatic noise removal, no AI needed
- Filter out: parked domains, default pages, CDN error pages, redirect-only hosts
- This happens inside Stage 2A (probing). Not a separate decision step.
- Almost everything alive passes through. This is cleanup, not prioritization.

### Decision Point 2: After Stage 2 (Discovery)
- This is the real decision. The AI reviews the full attack surface.
- AI sees: hosts, tech stacks, endpoints, parameters, secrets, cloud assets
- AI decides: what to test, with what tools, in what order

## Attack Surface Summary Format

The summary returned by bughound_get_attack_surface should be structured for AI reasoning:

```
{
  "workspace_id": "...",
  "target": "example.com",
  "target_type": "BROAD_DOMAIN",
  "stats": {
    "total_subdomains": 247,
    "live_hosts": 89,
    "unique_technologies": ["WordPress 6.4", "nginx 1.24", "GraphQL", "React"],
    "total_urls": 4521,
    "total_parameters": 312,
    "secrets_found": 7,
    "takeover_candidates": 2
  },
  "high_interest_targets": [
    {
      "host": "api.example.com",
      "reason": "GraphQL endpoint, no WAF, 15 unique parameters, API keys found in JS",
      "tech": ["GraphQL", "Node.js", "Express"],
      "endpoints_count": 45,
      "parameters_count": 15,
      "secrets": ["AWS_ACCESS_KEY in /static/js/app.js"]
    }
  ],
  "technologies_summary": { ... },
  "cloud_exposure": { ... },
  "potential_takeovers": [ ... ]
}
```

The "high_interest_targets" section is pre-filtered by simple heuristics (has parameters + has interesting tech + has secrets = high interest). But the final prioritization is the AI's job.

## Scan Plan Format

The AI submits a scan plan back via bughound_submit_scan_plan:

```
{
  "workspace_id": "...",
  "targets": [
    {
      "host": "api.example.com",
      "priority": 1,
      "test_classes": ["sqli", "xss", "ssrf", "graphql_injection"],
      "tools": ["nuclei", "sqlmap", "dalfox"],
      "specific_endpoints": ["/api/v1/users?id=", "/graphql"],
      "notes": "GraphQL with no auth, test introspection and injection"
    }
  ],
  "global_settings": {
    "max_concurrent": 3,
    "timeout_per_target": 300,
    "nuclei_severity": ["critical", "high", "medium"]
  }
}
```

## MCP Tools

### bughound_get_attack_surface
- Input: workspace_id
- Reads: all Stage 2 output from workspace
- Process: aggregates, computes stats, identifies high-interest targets
- Output: structured attack surface summary JSON
- This is a READ-ONLY operation. No scanning, no network calls.

### bughound_submit_scan_plan
- Input: workspace_id, scan_plan (JSON)
- Process: validate plan against workspace scope, check tools exist, store plan
- Output: validation result (approved / rejected with reasons)
- Writes: scan_plan.json to workspace
- Stage 4 reads this file to know what to execute.

## Key Design Notes

- Keep the attack surface summary concise but complete. The AI has limited context window. Don't dump 4000 URLs. Summarize and highlight what matters.
- The high_interest_targets heuristic is simple: more endpoints + more parameters + secrets found + interesting tech = higher interest score. This is just pre-sorting, not decision-making.
- Scan plan validation must check: all targets are within original scope, all tools referenced actually exist on the system, resource limits are reasonable.
- For the demo: this is the "wow" moment. The audience sees the AI analyzing the attack surface and making strategic decisions about what to test. Make the attack surface summary visually clean.
