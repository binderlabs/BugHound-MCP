# MCP Tool Patterns

## Naming Convention

All tools prefixed with `bughound_`. Namespaced by function:

```
bughound_{category}_{action}
```

Categories: init, workspace, job, enumerate, discover, analyze, execute, validate, report

Examples:
- bughound_init (no action needed, it's the entry point)
- bughound_workspace_list
- bughound_job_status
- bughound_enumerate
- bughound_discover
- bughound_get_attack_surface
- bughound_execute_tests
- bughound_validate_finding
- bughound_generate_report

## Tool Registration

All tools registered on a single MCP server in server.py. Internally organized by importing from stage modules:

```
server.py imports:
  - stages/enumerate.py -> registers bughound_enumerate, bughound_enumerate_deep
  - stages/discover.py -> registers bughound_discover
  - etc.
```

Each stage module exposes a `register_tools(server)` function that adds its tools to the server.

## Input/Output Patterns

### Input
- Every tool that operates on a workspace takes `workspace_id` as first parameter
- Optional parameters have sensible defaults
- Use Pydantic models for complex inputs (like scan plans)
- Validate inputs before doing anything. Return clear error if invalid.

### Output - Success
Every tool returns a consistent JSON structure:

```json
{
  "status": "success",
  "data": { ... },
  "message": "Human-readable summary",
  "workspace_id": "...",
  "files_written": ["subdomains/all.txt", "dns/records.json"]
}
```

### Output - Error
```json
{
  "status": "error",
  "error_type": "tool_not_found | invalid_input | execution_failed | timeout | scope_violation",
  "message": "Human-readable error description",
  "details": { ... }
}
```

### Output - Async Job Started
```json
{
  "status": "job_started",
  "job_id": "job_abc123",
  "message": "Deep enumeration started. Poll with bughound_job_status.",
  "estimated_time": "5-15 minutes"
}
```

## Sync vs Async Decision

| Condition | Behavior |
|-----------|----------|
| Single target, fast tool | Synchronous, return results directly |
| Single target, slow tool (dirfuzz deep) | Async job |
| Broad scope, any tool | Async job |
| Data retrieval (get_attack_surface, job_status) | Always synchronous |
| Report generation | Always synchronous |
| Validation (single finding) | Always synchronous |

Rule of thumb: if it might take more than 60 seconds, make it async.

## Error Handling

1. Tool binary not found -> return error with "tool_not_found" type + installation instructions
2. Tool execution failed -> return error with stderr output for debugging
3. Timeout -> return error with partial results if available
4. Scope violation -> return error explaining what was out of scope
5. Workspace not found -> return error with suggestion to run bughound_init first
6. No data from previous stage -> return error explaining which stage needs to run first

Never crash the MCP server. Every error is caught and returned as a structured error response.

## Tool Description Best Practices

Each tool's MCP description should clearly state:
- What the tool does in one sentence
- What stage it belongs to
- What inputs it needs
- Whether it's sync or async
- What prerequisite stages must have run first

Example:
```
"Discover attack surface for enumerated targets. Stage 2: probes live hosts, crawls URLs, 
extracts JS endpoints, finds secrets. Requires Stage 1 (enumerate) or Stage 0 (init for 
single hosts). Async for broad targets, sync for single hosts."
```

Good descriptions help the AI client make smart tool selection decisions.
