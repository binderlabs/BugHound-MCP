# BugHound Agent Mode — Implementation Plan

## Overview

Mode 3: `./bhound agent <target>` — AI-powered autonomous bug bounty hunting.
The AI thinks like an expert bug bounty hunter, adapts to the target, exploits
findings deeply, chains vulnerabilities, and writes contextual reports.

---

## Architecture

```
bughound/
├── agent.py            # Main agent loop + CLI integration
├── providers/
│   ├── __init__.py
│   ├── base.py         # Abstract AIProvider interface
│   ├── anthropic_provider.py   # Native Anthropic SDK
│   └── openai_compat.py        # OpenAI, Grok, OpenRouter (base_url swap)
├── agent_tools.py      # Tool definitions (function schemas for AI)
├── agent_prompts.py    # System prompt + phase-specific prompts
├── cli.py              # Add "agent" subcommand (already has placeholder)
├── server.py           # MCP server (UNCHANGED)
└── stages/             # Shared pipeline (UNCHANGED)
```

---

## Step-by-Step Build Order

### Step 1: Provider Abstraction (`providers/`)

```python
# providers/base.py
class AIProvider:
    async def chat(self, messages, tools=None) -> AIResponse: ...

class AIResponse:
    content: str              # Text response
    tool_calls: list[ToolCall] | None  # Tools AI wants to call
    usage: dict               # Token usage

class ToolCall:
    id: str
    name: str
    arguments: dict
```

```python
# providers/openai_compat.py — covers OpenAI, Grok, OpenRouter
PROVIDER_URLS = {
    "openai": "https://api.openai.com/v1",
    "grok": "https://api.x.ai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}

class OpenAICompatProvider(AIProvider):
    def __init__(self, api_key, base_url, model):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    async def chat(self, messages, tools=None) -> AIResponse:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,  # OpenAI function calling format
        )
        return self._parse(response)
```

```python
# providers/anthropic_provider.py — native Anthropic SDK
class AnthropicProvider(AIProvider):
    def __init__(self, api_key, model="claude-sonnet-4-6"):
        from anthropic import AsyncAnthropic
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model

    async def chat(self, messages, tools=None) -> AIResponse:
        response = await self.client.messages.create(
            model=self.model,
            messages=messages,
            tools=self._convert_tools(tools),  # Anthropic tool format
            max_tokens=4096,
        )
        return self._parse(response)
```

### Step 2: Agent Tools (`agent_tools.py`)

Define the tools the AI can call, in OpenAI function-calling format
(Anthropic provider converts internally).

```python
AGENT_TOOLS = [
    # === RECON ===
    {
        "type": "function",
        "function": {
            "name": "discover",
            "description": "Run Stage 2 discovery on the target. Returns live hosts, URLs, parameters, technologies, flags.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_surface",
            "description": "Get Stage 3 attack surface analysis. Returns parameter classification, attack chains, immediate wins, reasoning prompts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === TARGETED TESTING ===
    {
        "type": "function",
        "function": {
            "name": "run_technique",
            "description": "Run a specific testing technique. Use this for targeted testing based on your analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "technique_id": {"type": "string", "enum": [
                        "sqli_error_test", "reflected_xss_test", "lfi_test",
                        "rce_test", "ssrf_test", "ssti_test", "xxe_test",
                        "crlf_test", "idor_test", "path_idor_test",
                        "prototype_pollution_test", "open_redirect_test",
                        "header_injection_test", "security_headers_check",
                        "version_disclosure_check", "viewstate_mac_check",
                        "default_credentials_test", "sensitive_leakage_test",
                        # ... all 43 technique IDs
                    ]},
                },
                "required": ["workspace_id", "technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_test",
            "description": "Run ALL techniques (full Stage 4). Use this when you want comprehensive testing instead of targeted.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "test_classes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Which vulnerability classes to test. Omit for all.",
                    },
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === EXPLOITATION (agent-only, not in CLI/MCP) ===
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a custom HTTP request. Use for manual exploitation, chaining findings, verifying bypasses, extracting data from confirmed vulns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body (form-encoded or JSON string)"},
                    "body_type": {"type": "string", "enum": ["form", "json", "xml", "raw"], "default": "form"},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_sqli_data",
            "description": "Given a confirmed SQLi endpoint, attempt to extract data using UNION SELECT or error-based extraction.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string"},
                    "db_type": {"type": "string", "enum": ["mysql", "postgresql", "mssql", "oracle", "sqlite"]},
                    "query": {"type": "string", "description": "SQL query to extract, e.g. 'SELECT version()' or 'SELECT table_name FROM information_schema.tables'"},
                },
                "required": ["url", "param", "db_type", "query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_via_lfi",
            "description": "Given a confirmed LFI endpoint, read a specific file from the server.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string"},
                    "file_path": {"type": "string", "description": "File to read, e.g. /etc/passwd, /web.config, .env"},
                },
                "required": ["url", "param", "file_path"],
            },
        },
    },

    # === ANALYSIS ===
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Get all current findings. Use to review what's been found and decide next steps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_findings",
            "description": "Run Stage 5 validation on all findings using sqlmap/dalfox/curl.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === REPORT ===
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate final security reports (HTML, markdown, executive summary).",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": "Manually add a finding that you discovered through exploitation tools. Use when http_request reveals a vuln that automated techniques didn't catch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "vulnerability_class": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "endpoint": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "curl_command": {"type": "string"},
                    "impact": {"type": "string"},
                },
                "required": ["workspace_id", "vulnerability_class", "severity", "endpoint", "description", "evidence"],
            },
        },
    },
]
```

### Step 3: System Prompt (`agent_prompts.py`)

```python
SYSTEM_PROMPT = """You are an expert bug bounty hunter with 10+ years experience
on HackerOne and Bugcrowd. You approach every target methodically.

## Your methodology

PHASE 1 — RECON (understand before attacking)
- Study the tech stack, frameworks, endpoints, parameters
- Identify the most promising attack vectors based on technology
- Don't test WordPress vulns on a Flask app

PHASE 2 — TARGETED TESTING (precision over volume)
- Pick 5-8 most relevant techniques for THIS target
- Run them on the highest-value endpoints first
- If something looks interesting, go deeper

PHASE 3 — EXPLOITATION (prove impact)
- SQLi found? Extract actual data (tables, credentials)
- LFI found? Read sensitive files (config, .env, /etc/shadow)
- RCE found? Execute a safe proof command
- Auth bypass? Access admin panel and document what's exposed

PHASE 4 — CHAIN FINDINGS (connect the dots)
- LFI + credential exposure = full database access
- SQLi + admin creds = account takeover
- SSRF + cloud metadata = AWS key compromise
- Single findings are medium. Chains are critical.

PHASE 5 — REPORT (tell the story)
- Order by business impact, not severity count
- Each critical finding needs: evidence, reproduction steps, impact statement
- Write an executive summary a CISO can act on

## Rules
- NEVER test out of scope
- NEVER attempt denial of service
- NEVER modify or delete data
- Use safe proof commands only (id, whoami, hostname — not rm, drop, etc.)
- Stay within the target's authorized scope
- If you're unsure about a test, explain your reasoning and ask
"""

# Phase-specific prompts sent at each stage
RECON_PROMPT = """Discovery is complete. Here is the attack surface:

{attack_surface}

Based on this information:
1. What technology stack is the target running?
2. What are the 3 most promising attack vectors?
3. Which techniques should we run first and why?
4. What should we SKIP (irrelevant for this stack)?

Call run_technique() for your top priority tests, or run_full_test()
if you want comprehensive coverage."""

EXPLOITATION_PROMPT = """Testing complete. Here are the findings:

{findings}

For each confirmed or high-confidence finding:
1. Can you exploit it further? (extract data, read files, prove RCE)
2. Can you chain it with other findings?
3. What's the real business impact?

Use http_request(), extract_sqli_data(), or read_file_via_lfi() to
go deeper on promising findings."""

REPORT_PROMPT = """All testing and exploitation complete. Final findings:

{final_findings}

Write a concise executive summary covering:
1. The 3 most critical attack paths (with chains)
2. Business impact for each
3. Recommended priority for remediation

Then call generate_report() to create the formal deliverables."""
```

### Step 4: Agent Loop (`agent.py`)

```python
# Core agent loop — simplified pseudocode

async def run_agent(target, provider, api_key, model, verbose):
    ai = create_provider(provider, api_key, model)
    workspace_id = await init_workspace(target)

    # Phase 1: Recon (automated, no AI needed)
    print("[*] Phase 1: Reconnaissance")
    await run_discover(workspace_id)
    attack_surface = await get_attack_surface(workspace_id)

    # Phase 2: AI-driven testing
    print("[*] Phase 2: AI-driven testing")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": RECON_PROMPT.format(attack_surface=attack_surface)},
    ]

    # Agent tool-use loop
    max_iterations = 30  # Safety limit
    for i in range(max_iterations):
        response = await ai.chat(messages, tools=AGENT_TOOLS)

        if response.tool_calls:
            for tc in response.tool_calls:
                if verbose:
                    print(f"  [AI] {tc.name}({summarize_args(tc.arguments)})")

                # Execute the tool
                result = await execute_agent_tool(tc.name, tc.arguments, workspace_id)

                if verbose:
                    print(f"  [->] {summarize_result(result)}")

                # Add tool result back to conversation
                messages.append({"role": "assistant", "tool_calls": [tc]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})
        else:
            # AI finished — print final analysis
            print(f"\n{response.content}")
            break

    # Phase 3: Exploitation (AI continues with exploitation prompt)
    findings = await get_findings(workspace_id)
    messages.append({"role": "user", "content": EXPLOITATION_PROMPT.format(findings=findings)})

    for i in range(20):  # Exploitation loop
        response = await ai.chat(messages, tools=AGENT_TOOLS)
        if response.tool_calls:
            for tc in response.tool_calls:
                # Safety: scope check on http_request
                if tc.name == "http_request":
                    if not is_in_scope(tc.arguments["url"], target):
                        print(f"  [!] Blocked: {tc.arguments['url']} is out of scope")
                        continue
                result = await execute_agent_tool(tc.name, tc.arguments, workspace_id)
                messages.append(...)
        else:
            print(f"\n{response.content}")
            break

    # Phase 4: Report
    messages.append({"role": "user", "content": REPORT_PROMPT.format(final_findings=findings)})
    response = await ai.chat(messages, tools=AGENT_TOOLS)
    # ... handle report generation

    print(f"\n[*] Agent complete. Workspace: {workspace_id}")
```

### Step 5: CLI Integration

```python
# Add to cli.py argparse

agent_parser = subparsers.add_parser("agent", parents=[_common],
                                      help="AI-powered autonomous scanning")
agent_parser.add_argument("target", help="Target URL or domain")
agent_parser.add_argument("--provider", required=True,
                          choices=["anthropic", "openai", "grok", "openrouter"],
                          help="AI provider")
agent_parser.add_argument("--api-key", required=True, help="API key")
agent_parser.add_argument("--model", default=None,
                          help="Model name (default: provider's best)")
agent_parser.add_argument("--depth", default="light", choices=["light", "deep"])
agent_parser.add_argument("--max-iterations", type=int, default=50,
                          help="Max AI reasoning steps (default: 50)")
```

Usage:
```bash
./bhound agent https://target.com --provider openrouter --api-key sk-or-... --model anthropic/claude-sonnet-4
./bhound agent https://target.com --provider anthropic --api-key sk-ant-...
./bhound agent https://target.com --provider grok --api-key xai-... --model grok-3
```

### Step 6: Safety Controls

```python
# Scope enforcement — agent can only test in-scope targets
def is_in_scope(url: str, target: str) -> bool:
    """Ensure URL is within the target's domain."""
    target_domain = urlparse(target).hostname
    url_domain = urlparse(url).hostname
    return url_domain and (url_domain == target_domain or url_domain.endswith(f".{target_domain}"))

# Dangerous command blocklist — agent cannot run destructive commands
BLOCKED_COMMANDS = ["rm ", "drop ", "delete ", "truncate ", "shutdown", "format "]

# Iteration limit — prevent infinite loops
MAX_ITERATIONS = 50

# Token budget — stop if spending too much
MAX_TOKENS = 100_000  # ~$1-3 depending on model

# Read-only exploitation — agent proves impact without modifying data
```

---

## Default Models Per Provider

| Provider | Default Model | Notes |
|----------|---------------|-------|
| anthropic | claude-sonnet-4-6 | Best tool_use support |
| openai | gpt-4o | Good function calling |
| grok | grok-3 | xAI's latest |
| openrouter | anthropic/claude-sonnet-4 | Via routing |

---

## Dependencies

```
# Required (pick based on provider)
anthropic>=0.40.0     # For --provider anthropic
openai>=1.0.0         # For --provider openai/grok/openrouter

# Already installed
aiohttp               # For http_request tool
structlog             # Logging
```

No new heavy dependencies. Users only install the SDK for their chosen provider.

---

## Build Order

1. `providers/base.py` — abstract interface
2. `providers/openai_compat.py` — OpenAI/Grok/OpenRouter
3. `providers/anthropic_provider.py` — native Anthropic
4. `agent_tools.py` — tool definitions + executor
5. `agent_prompts.py` — system prompt + phase prompts
6. `agent.py` — main loop + phases
7. CLI integration in `cli.py` — add agent subcommand
8. Test with each provider

---

## What agent mode does NOT change

- `server.py` — MCP server untouched
- `stages/` — all stage functions unchanged
- `tools/` — all testing tools unchanged
- `cli.py` scan/recon/etc — unchanged
- Workspace format — same JSON structure

Agent mode is a new caller of the same pipeline, with AI reasoning between calls.

---

## After Agent Mode: Finalize Checklist

- [ ] E2E test all 3 targets via agent mode
- [ ] Verify MCP still works (no regressions)
- [ ] Update README with all 3 modes
- [ ] Record demo video
- [ ] Clean up workspace data
- [ ] Final commit + tag v1.0
