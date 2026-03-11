# BugHound Architecture

## Vision

BugHound is not another recon wrapper. It is the first AI-native bug bounty platform where the AI client reasons about targets, adapts strategy based on findings, and makes decisions a human pentester would make. The MCP server provides structured, intelligence-rich data. The AI provides the brain.

---

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                      AI CLIENT LAYER                     │
│          (Claude Desktop / Gemini CLI / Codex)           │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌───────────────────┐    │
│   │ Receives │  │ Reasons  │  │ Decides next step │    │
│   │ data     │──│ about    │──│ & calls next tool │    │
│   │ from MCP │  │ findings │  │                   │    │
│   └──────────┘  └──────────┘  └───────────────────┘    │
│         ▲                              │                 │
└─────────┼──────────────────────────────┼─────────────────┘
          │    MCP Protocol (JSON-RPC)   │
          │    Tool calls + responses    │
┌─────────┼──────────────────────────────┼─────────────────┐
│         │     BUGHOUND MCP SERVER      ▼                 │
│                                                          │
│   ┌──────────────────────────────────────────────┐      │
│   │              server.py (single process)       │      │
│   │                                               │      │
│   │  ┌─────────┐ ┌─────────┐ ┌──────────────┐   │      │
│   │  │ Stage 0 │ │ Stage 1 │ │   Stage 2    │   │      │
│   │  │  Init   │ │  Enum   │ │  Discover    │   │      │
│   │  └────┬────┘ └────┬────┘ └──────┬───────┘   │      │
│   │       │            │             │            │      │
│   │  ┌────┴────┐ ┌────┴────┐ ┌──────┴───────┐   │      │
│   │  │ Stage 3 │ │ Stage 4 │ │   Stage 5    │   │      │
│   │  │ Analyze │ │  Test   │ │  Validate    │   │      │
│   │  └────┬────┘ └────┬────┘ └──────┬───────┘   │      │
│   │       │            │             │            │      │
│   │       └────────────┴─────────────┘            │      │
│   │                    │                          │      │
│   │              ┌─────┴─────┐                    │      │
│   │              │  Stage 6  │                    │      │
│   │              │  Report   │                    │      │
│   │              └───────────┘                    │      │
│   └──────────────────────────────────────────────┘      │
│                          │                               │
│   ┌──────────────────────┴───────────────────────┐      │
│   │              CORE INFRASTRUCTURE              │      │
│   │                                               │      │
│   │  ┌────────────┐ ┌────────────┐ ┌──────────┐ │      │
│   │  │ tool_runner │ │ job_manager │ │workspace │ │      │
│   │  └────────────┘ └────────────┘ └──────────┘ │      │
│   └──────────────────────────────────────────────┘      │
│                          │                               │
│   ┌──────────────────────┴───────────────────────┐      │
│   │              EXTERNAL TOOL LAYER              │      │
│   │                                               │      │
│   │  subfinder  httpx  nuclei  gospider  ffuf    │      │
│   │  gau  waybackurls  jsluice  sqlmap  dalfox   │      │
│   │  wafw00f  crtsh  arjun  katana  puredns      │      │
│   └──────────────────────────────────────────────┘      │
│                          │                               │
│   ┌──────────────────────┴───────────────────────┐      │
│   │              WORKSPACE (filesystem)           │      │
│   │                                               │      │
│   │  workspaces/{target}_{uuid}/                  │      │
│   │    metadata.json | config.json | scan_plan    │      │
│   │    subdomains/ dns/ hosts/ urls/ secrets/ ... │      │
│   └──────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────┘
```

---

## The Intelligence Difference

What makes BugHound different from reconftw, sn1per, and every other recon framework:

```
TRADITIONAL RECON FRAMEWORK:
  Target -> [Run all tools in order] -> [Dump results] -> Done
  
  Problem: Same pipeline for every target. No adaptation. No reasoning.

BUGHOUND:
  Target -> [AI classifies target] 
         -> [AI picks relevant modules based on target type]
         -> [Tools return RICH structured data with patterns + anomalies]
         -> [AI REASONS about findings]
         -> [AI adapts strategy: "I found X, so let me try Y"]
         -> [AI correlates across stages]
         -> [AI generates targeted scan plan]
         -> [Tools execute scan plan]
         -> [AI validates and reports]
  
  Difference: The AI thinks between every step. It adapts. It correlates.
              It makes decisions a human pentester would make.
```

---

## Core Design Principles

1. **AI does the thinking, MCP does the doing.** No AI calls inside the server.
2. **Data richness over data volume.** Return patterns, anomalies, groupings. Not just lists.
3. **Scope + Depth are independent.** Target type decides modules. User decides intensity.
4. **Graceful degradation.** Missing tools are adapted around, not crashed on.
5. **Single server, namespaced tools.** One install, one config entry, everything works.
6. **Workspace is the contract.** Stages communicate through structured workspace files.

---

## Component Dependency Map

```
server.py
  ├── config/settings.py          (reads configuration)
  ├── core/target_classifier.py   (Stage 0 logic)
  ├── core/workspace.py           (workspace CRUD)
  ├── core/job_manager.py         (async job lifecycle)
  ├── core/tool_runner.py         (subprocess execution)
  ├── stages/enumerate.py         (Stage 1 orchestration)
  │     └── tools/recon/subfinder.py, assetfinder.py, crtsh.py, findomain.py
  ├── stages/discover.py          (Stage 2 orchestration)
  │     └── tools/recon/httpx.py, wafw00f.py
  │     └── tools/discovery/gospider.py, jsluice.py, arjun.py
  │     └── tools/recon/gau.py, waybackurls.py
  ├── stages/analyze.py           (Stage 3 data aggregation)
  ├── stages/test.py              (Stage 4 orchestration)
  │     └── tools/scanning/nuclei.py, ffuf.py
  ├── stages/validate.py          (Stage 5 orchestration)
  │     └── tools/scanning/sqlmap.py, dalfox.py
  ├── stages/report.py            (Stage 6 generation)
  └── schemas/models.py           (Pydantic models for everything)
```
