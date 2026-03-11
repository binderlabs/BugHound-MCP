# BugHound - AI-Powered Bug Bounty MCP Server

## Project Identity

BugHound is a single MCP server for AI-powered web bug bounty reconnaissance and vulnerability assessment. It provides a complete pipeline from target input to verified vulnerability report. The AI client (Claude, Gemini, Codex) orchestrates the pipeline by calling MCP tools sequentially, reasoning about results between stages.

Target milestone: Black Hat Arsenal demo, April 2026.

## Architecture: 7-Stage Pipeline

```
Stage 0: Initialize   -> Target classification + workspace creation
Stage 1: Enumerate     -> Subdomain discovery + DNS (skipped for single hosts)
Stage 2: Discover      -> Probe, crawl, dirfuzz, JS analysis, secrets, cloud assets
Stage 3: Analyze       -> Format attack surface for AI reasoning + accept scan plan
Stage 4: Test          -> Execute scan plan (nuclei, tech-specific checks)
Stage 5: Validate      -> Surgical verification (sqlmap, dalfox, etc.)
Stage 6: Report        -> Generate deliverables (bug bounty, technical, executive)
```

Stages collapse based on target type:
- Broad domain (*.example.com): all stages run
- Single host (dev.example.com): Stage 1 skipped, Stage 2 starts at probing
- Single endpoint (https://dev.example.com/api): Stage 1 skipped, Stage 2 crawls from path only
- URL list: Stage 1 skipped, batch probe and crawl

Depth (light/deep) and scope (target type) are independent axes.
- Scope = which modules run (determined by target classification)
- Depth = how aggressively each module runs (user-controlled)

## Single Server Design

One MCP server, one process, all tools namespaced by function:

```
Workspace:   bughound_init, bughound_workspace_list, bughound_workspace_get, bughound_workspace_delete
Jobs:        bughound_job_status, bughound_job_results, bughound_job_cancel
Recon:       bughound_enumerate, bughound_enumerate_deep, bughound_discover
Analysis:    bughound_get_attack_surface, bughound_submit_scan_plan
Testing:     bughound_execute_tests, bughound_test_single
Validation:  bughound_validate_finding
Reporting:   bughound_generate_report
```

~15 tools total. Clean, purposeful, no bloat.

## Project Structure

```
BugHound/
├── CLAUDE.md                  # THIS FILE - read first every session
├── PLAN.md                    # 10-day development plan with checkboxes
├── DEVLOG.md                  # Daily development journal
├── README.md
├── .claude/
│   └── skills/                # On-demand context (load per task)
│       ├── stage-0-init.md
│       ├── stage-1-enumerate.md
│       ├── stage-2-discover.md
│       ├── stage-3-analyze.md
│       ├── stage-4-test.md
│       ├── stage-5-validate.md
│       ├── stage-6-report.md
│       ├── mcp-tool-patterns.md
│       ├── tool-wrapper-guide.md
│       └── workspace-schema.md
├── bughound/
│   ├── server.py              # Single MCP server entry point
│   ├── config/
│   │   └── settings.py        # One config source of truth
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
│   │   └── discovery/         # gospider, jsluice, arjun, etc.
│   ├── schemas/
│   │   └── models.py          # Pydantic models for all data formats
│   └── utils/
│       └── helpers.py
├── tests/
├── _archive/                  # Archived code (not deleted, not active)
└── workspaces/                # Runtime data (gitignored)
```

## Hard Rules

1. NO internal AI calls. No OpenRouter, no Grok, no LLM calls inside the MCP server. The AI client does all reasoning. MCP server returns structured data only.
2. Pydantic validation on ALL stored JSON data. No unvalidated writes to workspace.
3. Every tool wrapper uses core/tool_runner.py. No direct subprocess calls in tool wrappers.
4. No hardcoded paths. All paths configurable via settings.py or environment variables.
5. Single workspace format only. Data-type-based organization (subdomains/, dns/, hosts/, urls/, etc.), NOT light/deep split.
6. Lazy directory creation. Directories created when data is written, not upfront.
7. All MCP tools return structured JSON responses. No raw text dumps.
8. Scope enforcement: tools must validate targets are in scope before execution.
9. Tool availability check before execution. Graceful "tool not found" message, not crash.
10. All background jobs have configurable timeouts and support cancellation.
11. Every MCP tool output should be optimized for AI reasoning, not just data dumping. Include patterns, anomalies, groupings, and suggested next steps in structured output.
12. Tool availability is a runtime constraint, not a hard requirement. The pipeline adapts to available tools gracefully.
13. Scope checking is mandatory before any active tool execution.

## Tech Stack

- Python 3.11+
- MCP SDK (mcp >= 0.1.0)
- Pydantic >= 2.0.0 (data validation)
- asyncio (async job management)
- aiofiles (async file I/O)
- structlog (structured logging)
- No database. Filesystem-based workspace storage with JSON files.

## Current Status

<!-- UPDATE THIS SECTION DAILY -->

**Phase:** Phase 0 - Foundation
**Current task:** Initial cleanup + project skeleton
**Completed:** Nothing yet (starting fresh refactor)
**Next:** Delete dead code, create new skeleton, build core infrastructure
**Blockers:** None

## Key Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-03-11 | Single MCP server | Simpler install, one config entry, better demo |
| 2026-03-11 | No internal AI calls | AI reasoning belongs at client layer, not MCP |
| 2026-03-11 | Data-type workspace | Avoids light/deep duplication and merge step |
| 2026-03-11 | Lazy dir creation | Clean workspace, no empty folders |
| 2026-03-11 | Scope + depth as independent axes | Target type decides modules, user decides intensity |
| 2026-03-11 | Decision engine runs twice | First pass: noise removal. Second pass: real prioritization |
| 2026-03-11 | 7 stages, stages collapse by target type | Single hosts skip enumeration, endpoints skip most |
