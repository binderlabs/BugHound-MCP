# Stage 4: Test

## Purpose

Executes the scan plan from Stage 3. Runs vulnerability scanners and checks against approved targets. Tools here are dumb workers. They run exactly what the scan plan says, nothing more.

## Critical Design Principle

No decision-making happens in this stage. If nuclei finds something, it logs it. It does NOT go off exploring further. That feedback loop (find something interesting -> re-recon -> test more) happens through the AI client, not inside the pipeline.

## Tool Mapping

The scan plan specifies test classes. Each class maps to tools and configurations:

| Test Class | Primary Tool | Secondary | Notes |
|-----------|-------------|-----------|-------|
| sqli | nuclei (sqli templates) | sqlmap (Stage 5) | nuclei for detection, sqlmap for validation |
| xss | nuclei (xss templates) | dalfox (Stage 5) | nuclei for detection, dalfox for validation |
| ssrf | nuclei (ssrf templates) | manual (interactsh callback) | Needs OOB callback server |
| lfi/rfi | nuclei (lfi templates) | - | |
| open_redirect | nuclei (redirect templates) | - | |
| graphql_injection | nuclei (graphql templates) | - | |
| subdomain_takeover | nuclei (takeover templates) | subjack | |
| exposed_panels | nuclei (panels templates) | - | |
| cve_specific | nuclei (cves templates) | - | Filter by detected tech versions |
| misconfig | nuclei (misconfigurations) | - | CORS, headers, methods |
| default_creds | nuclei (default-logins) | - | |
| file_exposure | nuclei (exposures) | - | .git, .env, backups |

Nuclei is the workhorse for Stage 4. It covers most test classes via template tags.

## Execution Logic

1. Read scan_plan.json from workspace
2. For each target in priority order:
   a. Map test_classes to nuclei template tags
   b. If specific_endpoints provided, test only those
   c. If no specific endpoints, test all discovered URLs for that host
   d. Run nuclei with appropriate severity filter and template tags
   e. If non-nuclei tools specified (ffuf for content discovery), run those too
3. Write raw results to workspace
4. Respect max_concurrent and timeout_per_target from scan plan

## Output

Written to workspace:
- vulnerabilities/scan_results.json: all findings from all tools
- vulnerabilities/by_host/{hostname}.json: findings grouped by host
- vulnerabilities/by_severity.json: findings grouped by severity

Each finding should include:
- finding_id: unique identifier
- host: affected host
- endpoint: affected URL/path
- vulnerability_class: sqli, xss, etc.
- severity: critical, high, medium, low, info
- tool: which tool found it
- template_id: nuclei template ID (if applicable)
- evidence: raw request/response or relevant output
- confidence: tool's confidence level
- needs_validation: boolean (true for most, false for high-confidence detections)

## MCP Tools

### bughound_execute_tests
- Input: workspace_id
- Reads: scan_plan.json from workspace
- For single target: can run synchronously if scan plan is small
- For broad scope: async job, returns job_id
- Output: findings count, severity breakdown, data written to workspace

### bughound_test_single
- Input: workspace_id, target_url, tool (nuclei|sqlmap|dalfox|ffuf), options (optional)
- Purpose: surgical testing of a specific endpoint with a specific tool
- The AI might call this directly: "run sqlmap against this parameter"
- Always synchronous (single target, single tool)
- Output: findings for that specific test

## Key Design Notes

- Nuclei template selection is critical. Don't blast all 8000+ templates at every target. Use the test_classes from scan plan to filter to relevant template tags.
- Tech-aware testing: if the scan plan says "WordPress detected", add wp-specific templates. If "GraphQL detected", add graphql templates. The AI should specify this in the scan plan, but the execution stage should also cross-reference against technologies.json from Stage 2.
- Rate limiting: some targets have rate limits or WAFs. The scan plan's global_settings should control concurrency. If a target starts returning 429s, back off.
- For the 10-day sprint: nuclei is the only must-have for Stage 4. Everything else is bonus.
