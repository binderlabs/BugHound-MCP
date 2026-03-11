# Tool Wrapper Guide

## Architecture

Every external CLI tool (subfinder, httpx, nuclei, etc.) is wrapped by a Python class that inherits from a common base. The base class provides: binary discovery, execution with timeout, output parsing, structured error handling.

## Base Tool (core/tool_runner.py)

The unified tool runner provides:

1. **Binary discovery**: check if tool exists on PATH, then check configured tool directories (from settings.py). No hardcoded paths like /home/kali/go/bin.
2. **Pre-flight check**: `is_available()` method returns True/False. Call this before execution to avoid runtime crashes.
3. **Execution**: async subprocess with configurable timeout. Captures stdout, stderr, return code.
4. **Output parsing**: each tool wrapper defines how to parse its output (JSON, line-delimited text, etc.)
5. **Error handling**: binary not found, execution timeout, non-zero exit, empty output. All return structured error objects, never raise unhandled exceptions.

## Tool Wrapper Structure

Each wrapper lives in `bughound/tools/{category}/{tool_name}.py` and defines:

- `name`: tool identifier string
- `binary_name`: what to look for on PATH (e.g., "subfinder")
- `is_available()`: check if binary exists
- `execute(target, options)`: run the tool, return parsed results
- `parse_output(raw_output)`: convert raw tool output to structured data

## Execution Flow

```
1. Check is_available() 
   -> If not: return ToolNotFoundError with install instructions

2. Build command arguments from input parameters
   -> Sanitize all inputs (no shell injection)

3. Run via asyncio.create_subprocess_exec (NOT shell=True)
   -> Set timeout from config or per-call override
   -> Capture stdout + stderr

4. Check return code
   -> Non-zero: return ToolExecutionError with stderr

5. Parse output via tool-specific parser
   -> Empty output: return empty result set (not error)
   -> Malformed output: return ToolParseError with raw output

6. Return structured result object
```

## Input Sanitization

CRITICAL: Never use `asyncio.create_subprocess_shell()`. Always use `asyncio.create_subprocess_exec()` with argument lists. User-provided targets go through validation:
- Domain: must match domain regex
- URL: must be valid URL format
- IP: must be valid IP format
- No shell metacharacters allowed in any input

## Output Format

Every tool wrapper returns a consistent result object:

```
{
  "tool": "subfinder",
  "target": "example.com",
  "execution_time_seconds": 12.5,
  "result_count": 47,
  "results": [ ... ],  # Tool-specific parsed data
  "raw_output_lines": 47,
  "errors": [],
  "warnings": []
}
```

## Timeout Strategy

| Tool Category | Default Timeout | Notes |
|--------------|----------------|-------|
| Passive recon (subfinder, crtsh) | 60s | API-based, should be fast |
| DNS resolution | 120s | Depends on subdomain count |
| HTTP probing (httpx) | 180s | Depends on host count |
| Crawling (gospider) | 300s per host | Can be slow on large sites |
| Directory fuzzing (ffuf) | 600s per host | Depends on wordlist size |
| Vulnerability scanning (nuclei) | 600s | Depends on template count |
| Validation tools (sqlmap, dalfox) | 300s | Surgical, single target |

All timeouts configurable via workspace config.json or settings.py.

## Adding a New Tool Wrapper

1. Create file in appropriate category: `bughound/tools/{category}/{tool_name}.py`
2. Define the class with binary_name and parse_output logic
3. Use tool_runner for execution (don't write custom subprocess code)
4. Add tool to the relevant stage module that calls it
5. Test: `is_available()` returns correct result, `execute()` handles success/failure/timeout

## PATH Configuration

Tool binary locations configured in settings.py:

```
TOOL_PATHS = [
    os.path.expanduser("~/go/bin"),      # Go tools
    os.path.expanduser("~/.local/bin"),   # pip-installed tools
    "/usr/local/bin",                      # system tools
    # User can add custom paths
]
```

The tool_runner prepends these to PATH when looking for binaries. No hardcoded absolute paths anywhere in tool wrappers.

## Common Patterns

### Tools that output JSON (nuclei -jsonl, httpx -json)
- Parse each line as JSON, collect into list
- Handle malformed lines gracefully (log warning, skip line)

### Tools that output line-delimited text (subfinder, gau)
- Split by newline, strip whitespace, deduplicate
- Filter empty lines

### Tools that output to a file (-o flag)
- Use tempfile for output path
- Read file after execution, then clean up
- Handle missing output file (tool crashed before writing)

### Tools with JSON and text modes
- Always prefer JSON output mode for structured parsing
- Fall back to text parsing if JSON mode not available
