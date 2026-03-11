# Stage 0: Initialize

## Purpose

First thing that runs. Takes user input, classifies the target, creates workspace, determines which downstream stages and modules are relevant.

## Target Classification

The classifier examines the input and returns one of these types:

| Input | Classification | Modules Skipped |
|-------|---------------|-----------------|
| example.com (wildcard scope) | BROAD_DOMAIN | None |
| dev.example.com | SINGLE_HOST | Enumeration (Stage 1) |
| https://dev.example.com/api/v1 | SINGLE_ENDPOINT | Enumeration + most of Discovery |
| file with 50 URLs | URL_LIST | Enumeration |
| 192.168.1.0/24 | IP_RANGE | Not supported in v1 (web-only) |

Classification output object should include:
- target_type: BROAD_DOMAIN | SINGLE_HOST | SINGLE_ENDPOINT | URL_LIST
- original_input: raw user input
- normalized_targets: list of targets to process
- stages_to_run: which stages are relevant
- depth: light | deep (user-specified or default to light)

## Workspace Creation

On init, create workspace directory with:
- metadata.json: target, classification, creation timestamp, current stage, tool versions
- config.json: user preferences (depth, excluded domains, API keys to use, tool overrides)

Directory structure uses data-type-based organization. Directories are created lazily (only when a tool writes to them), but metadata.json defines the full schema of what CAN exist.

Workspace naming: {target_sanitized}_{short_uuid}/
Example: example_com_a1b2c3d4/

## MCP Tools

### bughound_init
- Input: target (string), depth (light|deep, default light)
- Process: classify target, create workspace, determine pipeline
- Output: workspace_id, classification, stages_to_run, estimated_time

### bughound_workspace_list
- Input: status filter (optional: active|completed|archived)
- Output: list of workspaces with basic metadata

### bughound_workspace_get
- Input: workspace_id
- Output: full workspace metadata, current stage, results summary

### bughound_workspace_delete
- Input: workspace_id
- Output: confirmation

## Key Design Notes

- Classification is purely based on input format analysis. No DNS queries or network calls needed.
- If user provides a domain that looks broad but only has one subdomain in scope, that's still BROAD_DOMAIN. The enumeration stage will naturally find only one subdomain.
- Workspace config.json is the only place user preferences live. All downstream stages read from it. Never hardcode preferences in stage logic.
- metadata.json is write-only for the system. User doesn't modify it. It tracks execution state.
