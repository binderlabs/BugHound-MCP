# BugHound Development Log

## 2026-03-11 - Day 0: Architecture Planning

### Decisions Made
- Moving from 5 MCP servers to 1 single server with namespaced tools
- 7-stage pipeline: Init, Enumerate, Discover, Analyze, Test, Validate, Report
- Stages collapse based on target type (single host skips enumeration, etc.)
- Depth (light/deep) and scope (target type) are independent axes
- NO internal AI calls in MCP server. AI reasoning happens at client layer.
- Workspace uses data-type-based folders, NOT light/deep split
- Lazy directory creation (only when data is written)
- All tool wrappers use unified tool_runner
- All stored JSON validated with Pydantic
- Target: Black Hat Arsenal demo, April 2026

### Existing Codebase Assessment
- 29K lines of Python across 85 files
- ~10K lines actually usable (tool wrappers, light recon pipeline, workspace CRUD)
- 5 MCP servers exist (1 working, 1 broken, 3 stubs)
- 22 tool wrappers (13 recon + 8 scanning + 1 discovery)
- 4 critical bugs, 3 security issues, hardcoded API key
- Key code to KEEP: tool wrappers, light recon pipeline, workspace CRUD, job pattern, report templates
- Key code to DELETE: commander, workflow engine, AI analyzer/client, prioritization engine
- Key code to REWRITE: analyze server, decision engine, workspace structure, deep recon

### What's Next
- Phase 0 Day 1: cleanup dead code, create new project skeleton
- Phase 0 Day 2: build core infrastructure (tool_runner, job_manager, workspace)

---

<!-- APPEND NEW ENTRIES ABOVE THIS LINE -->
<!-- Format: ## YYYY-MM-DD - Day N: Brief Title -->
<!-- Include: Decisions Made, What Was Built, Issues Encountered, What's Next -->
