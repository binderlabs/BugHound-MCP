# Stage 6: Report

## Purpose

Generate deliverables from workspace data. Three report types: bug bounty submission, technical report, executive summary. Each pulls from the full workspace (recon data, findings, validation evidence) and formats appropriately.

## Report Types

### Bug Bounty Report
- Per-finding format optimized for HackerOne/Bugcrowd/Synack submission
- Each confirmed finding becomes one report entry
- Includes: title, severity (CVSS), description, reproduction steps, impact, remediation
- PoC evidence embedded (request/response, screenshots)
- Ready to copy-paste into platform submission form

### Technical Report
- Full assessment report for client delivery
- Scope definition, methodology, tools used
- All findings with technical detail
- Attack surface summary (from Stage 3)
- Risk ratings with CVSS scores
- Remediation recommendations per finding
- Appendices: full subdomain list, technology inventory, etc.

### Executive Summary
- High-level for non-technical stakeholders
- Key statistics: targets scanned, findings by severity
- Top risks in plain language
- Strategic recommendations
- Visual: severity distribution chart (if possible)

## Data Sources

The report generator reads from workspace:
- metadata.json: target info, scan dates, tools used
- config.json: scope definition
- hosts/live_hosts.json: attack surface scope
- hosts/technologies.json: tech inventory
- vulnerabilities/confirmed/: all confirmed findings with evidence
- vulnerabilities/false_positives.json: dismissed count (for accuracy stats)
- Any stage output needed for appendices

## Output

Written to workspace:
- reports/bug_bounty_report.md: markdown format, one section per finding
- reports/technical_report.md: full technical assessment
- reports/executive_summary.md: high-level summary
- reports/evidence/: directory with supporting files referenced by reports

## MCP Tools

### bughound_generate_report
- Input: workspace_id, report_type (bug_bounty|technical|executive)
- Reads: all relevant workspace data
- Process: aggregate data, format according to template
- Output: report content (markdown) + file path in workspace
- Always synchronous (report generation is fast, it's just formatting)

## Key Design Notes

- Reports should be generated from structured data, not from raw tool output. This is why Pydantic schemas matter. If the data is well-structured, report generation is just templating.
- Bug bounty reports need to be submission-ready. A researcher should be able to copy the output directly into HackerOne. This means proper markdown formatting, clear reproduction steps, and embedded evidence.
- For the 10-day sprint: bug bounty report is the must-have (it's the primary use case). Technical and executive reports are nice-to-have.
- The AI client can also help polish reports. The MCP tool generates the structured report, then the AI can refine the language, adjust severity assessments, or add context. This is another "AI + MCP" differentiator.
- Consider CVSS scoring: the MCP server can compute a base CVSS score from the finding data (vulnerability type, impact, exploitability), but the AI can refine it with contextual assessment.
