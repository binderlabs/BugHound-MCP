# Bug Bounty Essential Tool List

A concise, opinionated catalogue of the go‑to CLI utilities for reconnaissance and vulnerability discovery.

---

## Sub‑ / Asset Enumeration

| Tool | Short description |
|------|-------------------|
| **subfinder** | Fast passive sub‑domain enumerator that pulls from dozens of APIs and optionally brute‑forces DNS. |
| **assetfinder** | Quick sub‑domain discovery that queries multiple public sources with minimal setup. |
| **amass** | Comprehensive asset mapping (passive + active + graph DB) with powerful visualization options. |
| **findomain** | Rust‑based sub‑domain finder focused on speed and automatic result deduplication. |

## Port & Network Scanning

| Tool | Short description |
|------|-------------------|
| **nmap** | The classic network scanner for port, service and version detection. |
| **nmap‑scripts (NSE)** | Lua scripts that extend *nmap* for vulnerability checks and deep enumeration. |
| **masscan** | Internet‑scale TCP port scanner capable of scanning entire IPv4 space in minutes. |
| **rustscan** | Ultra‑fast Rust scanner that feeds open ports straight into *nmap* for service probing. |

## Live‑Host Probing

| Tool | Short description |
|------|-------------------|
| **httpx** | Multi‑protocol probe that checks if hosts are alive, collects TLS, title, status and technologies. |
| **httprobe** | Lightweight utility to test HTTP/S reachability for large host lists. |

## URL & Historical Enumeration

| Tool | Short description |
|------|-------------------|
| **waybackurls** | Pull archived URLs from Wayback Machine and other sources for attack‑surface expansion. |
| **gau (GetAllUrls)** | Aggregates URLs from CommonCrawl, Wayback and more; supports wildcard domains. |
| **unfurl** | Breaks URLs into components (paths, params) to feed wordlists and fuzzers. |

## Directory / Content Discovery

| Tool | Short description |
|------|-------------------|
| **ffuf** | Blazing‑fast fuzzer for directories, parameters and VHOSTs with dynamic auto‑calibration. |
| **dirsearch** | Python brute‑forcer with smart extension handling and resume capability. |
| **gobuster** | Go implementation covering directory, DNS and VHOST brute‑force modes. |
| **meg** | Wrapper that fetches every path for every host in parallel from a supplied list. |
| **fff** | “Faster Fast Finder” bulk directory brute‑forcer with real‑time filtering. |

## Pattern & Helper Utilities

| Tool | Short description |
|------|-------------------|
| **gf** | Grep‑For patterns: quickly filter interesting URLs or request logs. |
| **gf‑patterns** | Community pattern collection for *gf* (XSS, SQLi, SSRF, etc.). |
| **comb** | Combine, deduplicate and shuffle multiple wordlists efficiently. |
| **qsreplace** | Replace query‑string values in bulk URL lists to generate payload variations. |
| **gron** | Transforms JSON ↔ one‑item‑per‑line text for easy grepping and manipulation. |

## Vulnerability Scanning

| Tool | Short description |
|------|-------------------|
| **nuclei** | Template‑driven fast scanner covering misconfig, CVEs, fuzz and more. |
| **sqlmap** | Automated SQL‑injection detection, exploitation and database takeover. |
| **dalfox** | Parameter‑based fast XSS scanner with accurate payload generation. |
| **nikto** | Web server scanner for dangerous files, misconfigurations and outdated software. |

## Tech‑Fingerprinting / OSINT

| Tool | Short description |
|------|-------------------|
| **whatweb** | Identifies web technologies, frameworks and platforms used by a target. |
| **wappalyzer** | CLI wrapper that detects CMS, JS libraries and server stacks powering a site. |

---

**How to use this file**  
1. Clone or copy into your repo, then `grep` by category when wiring plugins.  
2. Feel free to append tool flags or personal notes in parentheses after each entry as your workflow evolves.

