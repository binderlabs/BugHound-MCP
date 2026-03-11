# Stage 5: Validate

## Purpose

Surgical verification of findings from Stage 4. For every finding that needs validation, use a specialized tool to confirm it's real and collect proof-of-concept evidence. This is where false positives die.

## Validation Matrix

| Vulnerability Class | Validation Tool | What It Does |
|--------------------|----------------|--------------|
| SQL Injection | sqlmap | Confirm injectable parameter, extract DB type, dump proof |
| XSS (Reflected) | dalfox | Confirm reflection, find working payload, capture PoC |
| XSS (Stored) | manual / dalfox | Harder to automate, may need AI guidance |
| SSRF | interactsh | Confirm OOB callback, prove server-side request |
| Subdomain Takeover | DNS check + claim attempt | Verify CNAME is dangling, attempt to claim (if safe) |
| Open Redirect | curl + redirect follow | Confirm redirect to external domain |
| LFI/RFI | curl with payload | Confirm file read, capture output |
| Exposed Secrets | manual verification | Check if API key/token is actually valid (carefully) |
| CORS Misconfig | curl with Origin header | Confirm reflected Origin, credentials allowed |
| Default Credentials | login attempt | Confirm access with default creds |

## Validation Flow

1. Read scan_results.json from workspace
2. Filter findings where needs_validation = true
3. For each finding, the AI decides:
   a. Validate with automated tool (sqlmap, dalfox, etc.)
   b. Mark as "needs manual review" (too complex for automation)
   c. Dismiss as false positive (AI reasoning based on evidence)
4. Run validation tool against specific endpoint + parameter
5. Classify result: CONFIRMED, FALSE_POSITIVE, NEEDS_MANUAL_REVIEW
6. For confirmed findings, collect full PoC evidence

## Evidence Collection

For each CONFIRMED finding, collect:
- Full HTTP request that triggers the vulnerability
- Full HTTP response showing the impact
- Screenshot (if visual, like XSS popup)
- Reproduction steps (curl command or equivalent)
- Impact description

## Output

Written to workspace:
- vulnerabilities/validated.json: all findings with validation status
- vulnerabilities/confirmed/: directory with one JSON per confirmed finding including full evidence
- vulnerabilities/false_positives.json: dismissed findings with reason
- vulnerabilities/manual_review.json: findings needing human review

Each confirmed finding includes:
- All fields from Stage 4 finding
- validation_status: CONFIRMED
- validation_tool: what tool confirmed it
- poc_request: full HTTP request
- poc_response: full HTTP response (or relevant excerpt)
- reproduction_steps: step-by-step to reproduce
- impact: what an attacker can do

## MCP Tools

### bughound_validate_finding
- Input: workspace_id, finding_id, tool (sqlmap|dalfox|interactsh|curl), options (optional)
- Reads: specific finding from scan_results.json
- Process: run validation tool against the finding's endpoint/parameter
- Output: validation result (confirmed/rejected) + evidence if confirmed
- Always synchronous (surgical, single finding)

## Key Design Notes

- Validation is per-finding, not per-host. The AI picks which findings to validate based on severity, confidence, and impact.
- sqlmap validation should use --batch --level=1 for quick confirmation, not full exploitation. We just need proof it's injectable.
- dalfox should use --skip-bav for speed. We need a working payload, not exhaustive testing.
- interactsh for SSRF/OOB needs a running callback server. Consider whether to bundle interactsh-client or use a hosted instance.
- For the 10-day sprint: sqlmap + dalfox are the must-haves. Everything else can be manual.
- Never validate by actually exploiting or causing damage. Proof of vulnerability, not proof of exploitation.
