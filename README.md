<h1 align="center">
  <img src="images/logo.png" alt="AIRecon" width="200">
  <br>
</h1>
<h4 align="center">AI-Powered Autonomous Penetration Testing Agent</h4>
<p align="center">
  <a href="https://ru.m.wikipedia.org/wiki/python">
    <img src="https://img.shields.io/badge/language-python-green.svg">
  </a>
  <a href="https://github.com/pikpikcu/airecon">
    <img src="https://img.shields.io/badge/version-v0.1.5-beta-green.svg">
  </a>
  <a href="https://github.com/pikpikcu/airecon/blob/master/LICENSE">
   <img src="https://img.shields.io/badge/LICENSE-red.svg">
  </a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
  <img src="https://img.shields.io/badge/LLM-Ollama%20(local)-orange.svg">
</p>

AIRecon is an autonomous penetration testing and bug bounty agent that combines a self-hosted **Large Language Model (Ollama)** with a **Kali Linux Docker sandbox**, native **Caido proxy integration**, a structured **RECON → ANALYSIS → EXPLOIT → REPORT pipeline**, and a real-time **Textual TUI** — completely offline, no API keys required.

---

## Table of Contents

- [Why AIRecon?](#why-airecon)
- [Architecture Overview](#architecture-overview)
- [Pipeline Phases](#pipeline-phases)
- [Tool Inventory](#tool-inventory-31-tools)
- [Skills Knowledge Base](#skills-knowledge-base-56-skills)
- [Model Requirements](#model-requirements)
- [Key Features](#key-features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [TUI Overview](#tui-overview)
- [Multi-Agent System](#multi-agent-system)
- [Session Management](#session-management)
- [Caido Integration](#caido-integration)
- [Browser Automation & Auth](#browser-automation--authentication)
- [Fuzzing Engine](#fuzzing-engine)
- [Reporting](#reporting)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)

---

## Why AIRecon?

Commercial API-based agents (Shannon, Strix cloud) require API keys and send your targets, payloads, and findings to third-party servers. For professional security engagements, this is unacceptable.

**AIRecon is built 100% for local, private operation.**

| Feature | AIRecon | Cloud-based agents |
|---------|---------|-------------------|
| API keys required | **No** | Yes |
| Target data sent to cloud | **No** | Yes |
| Works offline | **Yes** | No |
| Custom LLM models | **Yes** | No |
| Full tool control | **Yes** | Limited |
| Caido integration | **Native** | None |
| Session resume | **Yes** | Varies |

- **No API Keys** — No Anthropic, OpenAI, or Google dependency. Run everything on-prem.
- **Privacy First** — Target intelligence, tool output, and vulnerability reports never leave your machine.
- **Caido Native** — 5 built-in Caido tools: list, replay, automate (§FUZZ§ markers), findings, scope management.
- **Full Stack** — Kali sandbox + browser automation + custom fuzzer + Schemathesis API fuzzing + Semgrep SAST.
- **Session Resume** — Interrupt and resume any session. Findings persist across restarts.
- **Expert Knowledge Base** — 56 specialized skill files covering every major vuln class, protocol, and framework.

![Airecon](images/airecon.png)

---

## Architecture Overview

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                             AIRecon Architecture                                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                          Textual TUI (terminal)                             │
  │   Chat Panel │ Workspace Tree │ Vulnerability Panel │ Status Bar            │
  │   (colorized live output, tool cards, thinking spinner, file preview)       │
  └────────────────────────────────┬────────────────────────────────────────────┘
                                   │ SSE stream / HTTP polling
                                   ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                    FastAPI Proxy Server (127.0.0.1:3000)                    │
  │   /api/chat (SSE)  │  /api/status  │  /api/progress  │  /api/sessions       │
  └────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                           Agent Loop (core)                                 │
  │                                                                             │
  │  ┌────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐   │
  │  │ Pipeline Engine│  │  Session Manager │  │   Ollama LLM Client        │   │
  │  │ RECON          │  │  subdomains      │  │   qwen3.5:122b             │   │
  │  │  → ANALYSIS    │  │  live_hosts      │  │   temp=0.15 think=true     │   │
  │  │    → EXPLOIT   │  │  open_ports      │  │   ctx=65536 tokens         │   │
  │  │      → REPORT  │  │  technologies    │  │   retry on ResponseError   │   │
  │  │ (phase enforce)│  │  urls            │  └────────────────────────────┘   │
  │  └────────────────┘  │  vulnerabilities │                                   │
  │                      │  attack_chains   │  ┌───────────────────────────┐    │
  │  ┌────────────────┐  │  auth_cookies    │  │  Correlation Engine       │    │
  │  │ Context Re-    │  │  auth_tokens     │  │  port + tech + CVE rules  │    │
  │  │ inject (every  │  └──────────────────┘  │  86+ tech correlations    │    │
  │  │ 5 iterations)  │                        │  40+ port rules           │    │
  │  │ session_to_    │  ┌───────────────────┐ │  20+ CVE patterns         │    │
  │  │ context()      │  │ Anti-hallucination│ └───────────────────────────┘    │
  │  └────────────────┘  │ Failure recovery  │                                  │
  │                      │ Dedup (Jaccard)   │                                  │
  │                      └───────────────────┘                                  │
  └────────────────────────────────┬────────────────────────────────────────────┘
                                   │ tool dispatch (31 tools)
          ┌──────────────┬─────────┴──────────┬──────────────┬──────────────────┐
          ▼              ▼                     ▼              ▼                  ▼
  ┌──────────────┐ ┌──────────────┐  ┌──────────────┐ ┌──────────┐  ┌──────────────────┐
  │   execute    │ │browser_action│  │  web_search  │ │ Caido    │  │  Fuzzing Engine  │
  │   (Docker    │ │  Playwright  │  │  SearXNG /   │ │  Tools   │  │  quick_fuzz      │
  │   sandbox)   │ │  Chromium    │  │  DuckDuckGo  │ │  (5)     │  │  advanced_fuzz   │
  │              │ │  login_form  │  │  max 50 res  │ │          │  │  deep_fuzz       │
  │ subfinder    │ │  TOTP/OAuth  │  │  full dorks  │ │ list     │  │  schemathesis    │
  │ nmap/naabu   │ │  cookies     │  │  google,bing │ │ send     │  │  generate_       │
  │ httpx        │ │  tab mgmt    │  │  brave,gh    │ │ automate │  │  wordlist        │
  │ nuclei       │ │  JS inject   │  │  so,gscholar │ │ findings │  │                  │
  │ katana/ffuf  │ │  net logs    │  │  google_news │ │ scope    │  │ MutationEngine   │
  │ sqlmap       │ └──────────────┘  └──────────────┘ │          │  │ ExpertHeuristics │
  │ dalfox       │                                    │ §FUZZ§   │  │ ExploitChain     │
  │ wfuzz/ferox  │ ┌──────────────┐  ┌──────────────┐ │ markers  │  └──────────────────┘
  │ semgrep      │ │ create_file  │  │ code_analysis│ └──────────┘
  │ amass/massd  │ │ read_file    │  │ (Semgrep)    │  ┌──────────────────────────────┐
  │ theHarvester │ │ list_files   │  │ OWASP rules  │  │  Multi-Agent System          │
  └──────┬───────┘ │ create_vuln  │  │ p/security   │  │                              │
         │         │ _report      │  └──────────────┘  │  spawn_agent (specialist)    │
         ▼         └──────────────┘                    │    sqli/xss/ssrf/lfi/recon   │
  ┌──────────────────────────────┐                     │    exploit/analyzer/reporter │
  │  Kali Linux Docker Sandbox   │                     │                              │
  │  (airecon-sandbox image)     │                     │  run_parallel_agents         │
  │                              │                     │    semaphore-bounded         │
  │  60+ pre-installed tools     │                     │    multi-target              │
  │  SecLists / FuzzDB           │                     │                              │
  │  go tools / pip packages     │                     │  AgentGraph (DAG)            │
  │  /workspace/<target>/        │                     │    Recon → Analyzer          │
  │    output/   tools/          │                     │    → Exploiter + Specialist  │
  │    vulnerabilities/          │                     │    → Reporter                │
  └──────────────────────────────┘                     └──────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         Skills Knowledge Base                               │
  │  56 Markdown files  │  289 keyword→skill auto-mappings                      │
  │                                                                             │
  │  vulnerabilities/   sql_injection, xss, ssrf, idor, rce, xxe, csrf,         │
  │                     ssti, deserialization, http_smuggling, oauth_saml,      │
  │                     race_conditions, prototype_pollution, web_cache,        │
  │                     business_logic, privilege_escalation, mass_assignment,  │
  │                     information_disclosure, waf_detection, kubernetes...    │
  │                                                                             │
  │  technologies/      cloud_security, firebase_firestore, supabase            │
  │  frameworks/        nextjs, fastapi                                         │
  │  protocols/         graphql, active_directory, grpc, websocket              │
  │  payloads/          xss, sqli, ssrf, xxe, lfi, ssti, cmd_injection          │
  │  tools/             nmap, nuclei, sqlmap, dalfox, semgrep, caido,           │
  │                     browser_automation, scripting, advanced_fuzzing         │
  │  reconnaissance/    full_recon_sop                                          │
  └─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                     Session & Persistence Layer                             │
  │                                                                             │
  │  ~/.airecon/sessions/<session_id>.json                                      │
  │    subdomains, live_hosts, open_ports, technologies, urls                   │
  │    vulnerabilities (Jaccard dedup, configurable threshold)                  │
  │    attack_chains, auth_cookies, auth_tokens, completed_phases               │
  │                                                                             │
  │  Resume: airecon start --session <id>                                       │
  │  Session context re-injected every 5 iterations (anti context-loss)         │
  └─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                    SearXNG Self-Hosted Search (optional)                    │
  │                                                                             │
  │  docker.io/searxng/searxng  │  port 8080  │  auto-managed lifecycle         │
  │                                                                             │
  │  Engines: google, bing, duckduckgo, brave, startpage, github, stackoverflow │
  │           reddit, google_scholar, google_news                               │
  │                                                                             │
  │  Full dork support: site:, ext:, inurl:, intitle:, filetype:, intext:       │
  │  Fallback: DuckDuckGo (limited operators, rate-limited)                     │
  └─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                      Caido Proxy Integration                                │
  │                                                                             │
  │  127.0.0.1:48080/graphql  │  loginAsGuest token (auto-cached)               │
  │                                                                             │
  │  caido_list_requests   — query history with HTTPQL filters                  │
  │  caido_send_request    — replay/modify HTTP requests (asyncio.timeout 60s)  │
  │  caido_automate        — Burp Intruder-style fuzzing, §FUZZ§ byte offsets   │
  │  caido_get_findings    — retrieve annotated vulnerability findings          │
  │  caido_set_scope       — configure allowlist/denylist for capture           │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Phases

AIRecon operates through a structured 4-phase state machine. Each phase has specific objectives, recommended tools, and transition criteria tracked automatically from tool output.

```
RECON (max 500 iter)
  Objective: Enumerate attack surface
  Criteria:  subdomains_discovered + ports_scanned + recon_artifacts_saved
  Tools:     execute (subfinder/httpx/nmap/katana/ffuf), web_search, browser_action
      │
      ▼ (60% criteria met + min 10 iterations)
ANALYSIS (max 300 iter)
  Objective: Identify injection points, misconfigs, tech stack
  Criteria:  urls_collected + technologies_identified
  Tools:     execute, browser_action, code_analysis (Semgrep), read_file
      │
      ▼
EXPLOIT (max 800 iter)
  Objective: Test and confirm vulnerabilities
  Criteria:  vulnerabilities_tested
  Tools:     execute, quick_fuzz, advanced_fuzz, deep_fuzz, schemathesis_fuzz,
             caido_send_request, caido_automate, spawn_agent, create_vulnerability_report
      │
      ▼
REPORT (max 100 iter)
  Objective: Document all confirmed findings
  Criteria:  reports_generated
  Tools:     create_vulnerability_report, create_file, read_file
```

Phase guidance is **soft-enforced**: exploit-only tools used in earlier phases receive a `[PHASE GUIDANCE]` warning injected into the LLM context, but execution is not blocked.

**Checkpoints** run automatically during the agent loop:
- Every **5 iterations** — pipeline phase evaluation
- Every **10 iterations** — full self-evaluation of progress
- Every **15 iterations** — conversation context compression to prevent context overflow

---

## Tool Inventory (31 tools)

| Category | Tool | Description |
|----------|------|-------------|
| **Shell execution** | `execute` | Full Kali Linux shell in Docker sandbox, sudo access, 60+ preinstalled tools |
| **Browser** | `browser_action` | Playwright/Chromium: navigate, click, type, scroll, JS execution, PDF save, network logs, source view |
| **Browser auth** | (sub-actions) | `login_form` (auto selector discovery), `handle_totp` (RFC 6238), `oauth_authorize`, `save_auth_state`, `inject_cookies` |
| **Search** | `web_search` | SearXNG (full Google dork operators) or DuckDuckGo fallback, up to 50 results |
| **Workspace** | `create_file` | Write arbitrary files to `/workspace/<target>/` |
| **Workspace** | `read_file` | Read files from workspace |
| **Workspace** | `list_files` | List directory contents in workspace |
| **Reporting** | `create_vulnerability_report` | CVSS-scored Markdown report with PoC validation, evidence requirements, optional `suggested_fix` code snippet |
| **Fuzzing** | `quick_fuzz` | Fast, targeted parameter fuzzing |
| **Fuzzing** | `advanced_fuzz` | Multi-vector fuzzing with heuristic selection |
| **Fuzzing** | `deep_fuzz` | Exhaustive fuzzing with ExploitChainEngine |
| **Fuzzing** | `generate_wordlist` | Context-aware wordlist generation |
| **Fuzzing** | `schemathesis_fuzz` | OpenAPI/Swagger schema-aware API fuzzing — tests all documented endpoints for crashes, validation failures, auth bypass |
| **Caido** | `caido_list_requests` | Query Caido HTTP history with HTTPQL filters |
| **Caido** | `caido_send_request` | Replay and modify HTTP requests (60s timeout) |
| **Caido** | `caido_automate` | Burp Intruder-style automation with `§FUZZ§` byte markers (90s timeout) |
| **Caido** | `caido_get_findings` | Retrieve annotated vulnerability findings from Caido |
| **Caido** | `caido_set_scope` | Configure allowlist/denylist for traffic capture |
| **Static analysis** | `code_analysis` | Semgrep SAST: `p/owasp-top-ten`, `p/security-audit`, custom rules |
| **Multi-agent** | `spawn_agent` | Specialist subagent with depth=1 isolation: `sqli`, `xss`, `ssrf`, `lfi`, `recon`, `exploit`, `analyzer`, `reporter` |
| **Multi-agent** | `run_parallel_agents` | Concurrent multi-target assessment with semaphore-bounded parallelism |

---

## Skills Knowledge Base (56 Skills)

Skills are Markdown files containing expert-level procedures, payloads, and techniques. They are automatically loaded into the LLM context based on **289 keyword → skill mappings** detected in the user's prompt or current findings.

### Vulnerabilities (32 skills)

| Skill | Coverage |
|-------|----------|
| `sql_injection` | Error-based, blind, time-based, OOB, WAF bypass, SQLMap advanced |
| `xss` | Reflected, stored, DOM, mutation, CSP bypass, filter evasion |
| `ssrf` | Cloud metadata, protocol wrappers, DNS rebinding, blind SSRF |
| `idor` | Direct object reference, mass assignment, broken function level auth |
| `rce` | Command injection chains, deserialization gadgets, template exec |
| `ssti` | Jinja2, Twig, Freemarker, Smarty, Pebble template injection |
| `xxe` | OOB exfil, billion laughs, SVG/XLSX vectors, DTD injection |
| `csrf` | Token bypass, SameSite confusion, JSON CSRF, multipart |
| `oauth_saml` | Authorization code abuse, implicit flow, SAML assertion manipulation |
| `deserialization` | Java gadget chains, PHP object injection, Python pickle, .NET |
| `http_smuggling` | CL.TE, TE.CL, TE.TE desync, request tunneling |
| `race_conditions` | Limit bypass, TOCTOU, last-write-wins, batch operations |
| `prototype_pollution` | Client-side, server-side (Node.js), lodash/merge sinks |
| `web_cache_poisoning` | Header injection, cache key normalization, CPDoS |
| `business_logic` | 7-step testing procedure, price manipulation, workflow bypass |
| `privilege_escalation` | Vertical/horizontal, JWT privilege claims, role confusion |
| `mass_assignment` | Hidden fields, PUT/PATCH body injection, GraphQL mutations |
| `information_disclosure` | Debug endpoints, stack traces, version headers, git exposure |
| `waf_detection` | Fingerprinting, bypass techniques, encoding evasion |
| `kubernetes` | RBAC misconfig, etcd exposure, container escape, service account abuse |
| `subdomain_takeover` | DNS dangling, unclaimed cloud resources, CNAME chains |
| `path_traversal_lfi_rfi` | Path normalization bypass, PHP wrappers, log poisoning |
| `insecure_file_uploads` | MIME type bypass, polyglot files, extension confusion |
| `open_redirect` | URL parsers, parameter abuse, OAuth redirect_uri |
| `authentication_jwt` | Algorithm confusion (RS256→HS256), none alg, weak secrets, kid injection |
| `broken_function_level_authorization` | Admin endpoint enumeration, HTTP verb tampering |
| `supply_chain` | Dependency confusion, typosquatting, malicious packages |
| `websocket` | WS hijacking, CSWSH, protocol downgrade, message injection |
| `grpc` | Proto enumeration, reflection API, auth bypass, injection |
| `active_directory` | Kerberoasting, AS-REP roasting, BloodHound, lateral movement |
| `exploitation` | General post-exploitation, pivoting, C2 patterns |
| `api_testing` | REST/SOAP/GraphQL parameter discovery, verb tampering, rate limit |

### Payloads (7 files)

Pre-built payload collections for: `xss`, `sqli`, `ssrf`, `xxe`, `lfi`, `ssti`, `command_injection`

### Technologies (3 skills)

`cloud_security` (AWS/GCP/Azure misconfigs), `firebase_firestore` (NoSQL injection, auth bypass), `supabase` (row-level security bypass, API key abuse)

### Frameworks (2 skills)

`nextjs` (middleware bypass, server actions, SSRF via redirects), `fastapi` (OpenAPI exposure, dependency injection abuse)

### Protocols (2 skills)

`graphql` (introspection, batching abuse, IDOR via aliases), `active_directory` (see above)

### Tools (9 skills)

Deep usage guides for: `nmap`, `nuclei`, `sqlmap`, `dalfox`, `semgrep`, `caido`, `browser_automation`, `scripting`, `advanced_fuzzing`

### Reconnaissance (1 skill)

`full_recon_sop` — 19KB Standard Operating Procedure covering full-cycle recon with concrete success criteria, tool sequencing, and artifact requirements

---

## Model Requirements

**Not all Ollama models will work.** AIRecon requires two hard capabilities:

1. **Extended thinking / reasoning** — The model must support `<think>` blocks (`think=true` in Ollama). Without deep reasoning, the agent loses the ability to plan multi-step attack chains, debug tool failures, and follow scope rules under complex contexts.
2. **Reliable tool-calling** — The model must consistently produce well-formed JSON tool calls. Models that hallucinate tool names or produce malformed arguments will stall the agent loop.

> **Minimum model size: 30B parameters.** Models below 30B frequently hallucinate tool output, invent CVEs, skip scope rules, and produce incomplete function calls. **qwen3:14b is NOT recommended for real engagements.**

### Recommended Models

| Model | Pull Command | Parameters | VRAM | Notes |
|-------|-------------|-----------|------|-------|
| **Qwen3.5 122B** | `ollama pull qwen3.5:122b` | 122B | 48+ GB | Best quality — requires high-end hardware |
| **Qwen3 32B** | `ollama pull qwen3:32b` | 32B | 20 GB | **Recommended minimum** — good balance |
| **Qwen3 30B (A3B MoE)** | `ollama pull qwen3:30b-a3b` | 30B | 16 GB | Lower VRAM, comparable reasoning to 32B |

### Minimum Hardware

| Model | RAM | VRAM | Notes |
|-------|-----|------|-------|
| `qwen3:32b` | 32 GB | 20 GB | NVIDIA GPU strongly recommended |
| `qwen3:30b-a3b` | 24 GB | 16 GB | MoE — lower active params, faster inference |
| `qwen3.5:122b` | 80 GB | 48+ GB | Multi-GPU or CPU+GPU offload required |

### Known Issues

| Model | Problem |
|-------|---------|
| **DeepSeek R1** | Incomplete function calls, sticking/looping logic |
| **Models < 30B** | High hallucination rate — unreliable for full recon |
| **Models < 7B** | Cannot reliably format tool calls — not supported |
| **Generic chat models** (llama3, mistral, phi) | No reasoning support, will not follow agent scope rules |

---

## Key Features

- **Autonomous Pipeline** — RECON → ANALYSIS → EXPLOIT → REPORT with automatic phase transitions based on real findings, not iteration counts.
- **Session Persistence & Resume** — All findings (subdomains, ports, technologies, vulns, auth tokens) are saved to `~/.airecon/sessions/`. Resume with `airecon start --session <id>`.
- **Anti Context-Loss** — Full session data (`session_to_context()`) is re-injected into the LLM context every 5 iterations, preventing "lost in the middle" degradation on long runs.
- **Caido Native Integration** — 5 dedicated tools for the Caido HTTP proxy: replay, Intruder-style fuzzing with `§FUZZ§` markers, findings, scope management.
- **Browser Authentication** — login_form with selector auto-discovery, TOTP (RFC 6238, no external dep), OAuth flow, cookie injection, auth state persistence.
- **Custom Fuzzing Engine** — MutationEngine + ExpertHeuristics + ExploitChainEngine with 1000+ payloads per category. Zero-day discovery patterns built-in.
- **API Schema Fuzzing** — Schemathesis integration: auto-discovers OpenAPI/Swagger specs, generates test cases for every documented endpoint, checks for crashes/validation failures/auth bypass.
- **Technology Fingerprinting** — Parses whatweb, httpx `-tech-detect`, and nuclei output into structured `session.technologies`. Feeds the CVE correlation engine automatically.
- **Correlation Engine** — 86+ technology rules, 40+ port-based rules, 20+ CVE patterns. Fires automatically when fingerprinting completes.
- **Skills Knowledge Base** — 56 specialized Markdown files with expert procedures. Auto-loaded based on 289 keyword → skill mappings. Covers SQLi, XSS, SSRF, IDOR, business logic, race conditions, JWT, OAuth, GraphQL, WebSockets, Kubernetes, supply chain, and more.
- **Multi-Agent Orchestration** — `spawn_agent` for specialist subagents (sqli/xss/ssrf/lfi/recon/exploit/analyzer/reporter). `run_parallel_agents` for concurrent multi-target assessment. `AgentGraph` for DAG-based sequential pipelines.
- **Colorized TUI** — Live streaming output with pattern-based colorization: open ports (blue), CVEs (orange bold), errors (red), findings (orange), subdomains (blue), success (teal). Tool cards with left-accent borders (amber=running, green=done, red=error).
- **SearXNG Integration** — Self-hosted search with full Google dork operator support (`site:`, `ext:`, `inurl:`, `intitle:`, `filetype:`). Multi-engine: Google, Bing, DuckDuckGo, Brave, GitHub, Stack Overflow, Google News, Reddit, Google Scholar. Falls back to DuckDuckGo if unavailable.
- **Verified Reporting** — Strict PoC validation: `poc_script_code` >50 chars with real URL, `poc_description` with HTTP status evidence, `technical_analysis` >80 chars. Reports rejected if unverified language detected. Optional `suggested_fix` code snippet for developers.

---

## Installation

### Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Python | 3.10+ | System Python recommended |
| Docker | 20.10+ | Must be running before first launch |
| Ollama | Latest | Running locally or remote endpoint |
| Poetry | 1.4+ | Auto-installed by `install.sh` if missing |

### Step 1 — Clone and install

```bash
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh
```

The install script:
1. Installs Poetry if not found
2. Removes any previous AIRecon installation
3. Runs `poetry install` to resolve dependencies
4. Installs Playwright Chromium browser
5. Builds the wheel and installs to `~/.local/bin`

### Step 2 — Pull an Ollama model

```bash
# Recommended minimum (32B)
ollama pull qwen3:32b

# Best quality (requires high-end GPU)
ollama pull qwen3.5:122b

# Lower VRAM option (MoE architecture)
ollama pull qwen3:30b-a3b
```

### Step 3 — Verify PATH

```bash
# Add to ~/.bashrc or ~/.zshrc if needed
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
airecon --version
```

### Optional: Docker sandbox image

The Kali sandbox is built automatically on first run (`docker_auto_build: true` by default). To build manually:

```bash
docker build -t airecon-sandbox airecon/containers/kali/
```

### Optional: SearXNG (recommended for dorking)

AIRecon can auto-manage a SearXNG container for full Google dork support:

```bash
# Add to ~/.airecon/config.json:
"searxng_url": "http://localhost:8080"
```

AIRecon will pull and start the SearXNG container automatically on first use. Or start it manually:

```bash
docker run -d --name searxng -p 8080:8080 searxng/searxng
```

---

## Configuration

AIRecon reads `~/.airecon/config.json`. Auto-generated with defaults on first run.

```json
{
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_model": "qwen3.5:122b",
    "ollama_timeout": 1900.0,
    "ollama_num_ctx": 65536,
    "ollama_num_ctx_small": 32768,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 16384,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "proxy_host": "127.0.0.1",
    "proxy_port": 3000,
    "command_timeout": 900.0,
    "docker_image": "airecon-sandbox",
    "docker_auto_build": true,
    "tool_response_role": "tool",
    "deep_recon_autostart": true,
    "agent_max_tool_iterations": 500,
    "agent_repeat_tool_call_limit": 2,
    "agent_missing_tool_retry_limit": 2,
    "agent_plan_revision_interval": 30,
    "allow_destructive_testing": true,
    "browser_page_load_delay": 1.0,
    "ollama_keep_alive": "30m",
    "searxng_url": "http://localhost:8080",
    "searxng_engines": "google,bing,duckduckgo,brave,google_news,github,stackoverflow",
    "vuln_similarity_threshold": 0.7
}
```

### Key Settings Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `ollama_temperature` | `0.15` | Keep at `0.1`–`0.2` for tool-calling agents. Higher values cause hallucination. |
| `ollama_enable_thinking` | `true` | Enable `<think>` blocks for reasoning models (qwen3). |
| `ollama_num_ctx` | `65536` | Context window in tokens. Reduce if VRAM is limited (try `32768`). |
| `ollama_num_predict` | `16384` | Max tokens per LLM response. |
| `ollama_keep_alive` | `"30m"` | How long Ollama keeps the model loaded. `0` = unload immediately. |
| `deep_recon_autostart` | `true` | Bare domain inputs (e.g. `example.com`) auto-expand to full recon. |
| `allow_destructive_testing` | `true` | Unlocks aggressive/destructive testing modes (SQLi confirm, RCE chains). |
| `command_timeout` | `900.0` | Max seconds a single shell command can run inside Docker. |
| `searxng_url` | `""` | SearXNG endpoint. Empty = DuckDuckGo fallback (limited dork support). |
| `vuln_similarity_threshold` | `0.7` | Jaccard similarity threshold for vulnerability deduplication (0.0–1.0). |
| `agent_max_tool_iterations` | `500` | Hard cap on total tool calls per session. |
| `agent_repeat_tool_call_limit` | `2` | Max consecutive identical tool calls before forcing a different action. |
| `proxy_port` | `3000` | FastAPI backend port. Change if 3000 is in use. |

### Remote Ollama (GPU server)

```json
{
    "ollama_url": "http://192.168.1.100:11434",
    "ollama_model": "qwen3.5:122b"
}
```

---

## Usage

### Start the TUI

```bash
airecon start
```

### Resume a session

```bash
airecon start --session <session_id>
```

Session IDs are shown in the TUI title bar and stored as `~/.airecon/sessions/<id>.json`.

### Example Prompts

**Specific task** (agent runs one focused operation):

```
find subdomains of example.com
scan ports on 10.0.0.1
run nuclei on output/live_hosts.txt
check for XSS on https://example.com/login
test SQL injection on https://example.com/api/login parameter: username
fuzz https://example.com/api/v1/users for IDOR
run schemathesis on https://example.com/openapi.json
analyze /workspace/example.com/output/source.js for vulnerabilities
```

**Full recon** (agent follows the complete RECON → ANALYSIS → EXPLOIT → REPORT pipeline):

```
full recon on example.com
pentest https://api.example.com
bug bounty recon on example.com — find everything
comprehensive security assessment on https://target.com
```

**Authenticated testing:**

```
login to https://example.com/login with admin@example.com / password123 then test for IDOR
test https://app.example.com with TOTP: JBSWY3DPEHPK3PXP
inject auth cookies for https://example.com then run nuclei
```

**Multi-agent tasks:**

```
spawn an XSS specialist on https://example.com/search
run parallel recon on: example.com, sub.example.com, api.example.com
use an analyzer agent to review all findings in workspace/example.com
```

**Caido-based testing:**

```
replay request #1234 from Caido with a modified Authorization header
use Caido to fuzz the username parameter in request #45 with §FUZZ§ markers
list all POST requests in Caido history for example.com
```

**OSINT / dork-based:**

```
find exposed admin panels for example.com using Google dorks
search for CVE-2024-XXXXX PoC on GitHub
look for sensitive files indexed by Google for example.com
```

## Multi-Agent System

### spawn_agent

Spawns a depth=1 specialist agent focused on a single vulnerability class:

```
Specialists: sqli | xss | ssrf | lfi | recon | exploit | analyzer | reporter
```

The main agent continues its pipeline while the specialist digs deep into its domain. Results are merged back into the session on completion.

### run_parallel_agents

Concurrent multi-target assessment with semaphore-bounded parallelism:

```
run parallel recon on: target1.com, target2.com, target3.com
```

Each target gets its own isolated agent with a separate workspace. Findings are aggregated at the end.

### AgentGraph (DAG)

Sequential multi-agent pipelines via directed acyclic graph:

```
Recon Agent → Analyzer Agent → Exploiter Agent + Specialist Agents → Reporter Agent
```

Used for fully automated end-to-end assessments on complex targets.

---

## Session Management

All session data is stored at `~/.airecon/sessions/<session_id>.json`:

```json
{
    "session_id": "abc123",
    "target": "example.com",
    "subdomains": ["sub1.example.com", "api.example.com"],
    "live_hosts": ["https://sub1.example.com"],
    "open_ports": {"sub1.example.com": [80, 443, 8080]},
    "technologies": {"sub1.example.com": ["nginx/1.24", "PHP/8.1", "Laravel"]},
    "urls": ["https://sub1.example.com/api/v1/users"],
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "endpoint": "/api/login",
            "severity": "HIGH",
            "cvss": 9.1,
            "confirmed": true
        }
    ],
    "attack_chains": [],
    "auth_cookies": {},
    "auth_tokens": {},
    "completed_phases": ["RECON", "ANALYSIS"]
}
```

### Deduplication

Vulnerabilities are deduplicated using **Jaccard similarity** on title + endpoint + description. The threshold is configurable (`vuln_similarity_threshold: 0.7`). Set lower (e.g. `0.5`) to be more aggressive about deduplication.

### Context Re-injection

Every 5 iterations, `session_to_context()` re-injects the full session summary into the LLM's context window. This prevents "context loss" where the model forgets earlier findings on long runs.

---

## Caido Integration

AIRecon connects to Caido at `127.0.0.1:48080/graphql` using auto-managed session tokens. Caido must be running before launching AIRecon.

### HTTPQL Filter Examples

```
# List all POST requests to /api
caido_list_requests filter="method:POST AND path:/api"

# Find requests with specific header
caido_list_requests filter="header:Authorization AND host:example.com"
```

### §FUZZ§ Automation

```
# Fuzz a parameter using Caido Automate
caido_automate request_id=1234 payload_list=["' OR 1=1--", "SLEEP(5)", "' UNION SELECT"]
```

The `§FUZZ§` markers define fuzz points by byte offset in the raw HTTP request, identical to Burp Suite Intruder.

---

## Browser Automation & Authentication

### Supported Auth Methods

| Method | Tool Action | Notes |
|--------|-------------|-------|
| Form login | `login_form` | Auto-discovers username/password selectors |
| TOTP (2FA) | `handle_totp` | RFC 6238 — no external libraries required |
| OAuth flows | `oauth_authorize` | Handles redirect, token exchange |
| Cookie injection | `inject_cookies` | Load saved cookies from auth state |
| Auth state persistence | `save_auth_state` | Saves cookies + local storage to disk |

### Example: Authenticated Scan

```
# Step 1: Login
browser_action: login_form url=https://example.com/login username=admin@example.com password=secret123

# Step 2: Save state
browser_action: save_auth_state path=workspace/example.com/auth.json

# Step 3: Run authenticated nuclei
execute: nuclei -u https://example.com -H "Cookie: session=<cookie>" -t nuclei-templates/
```

---

## Fuzzing Engine

### Architecture

```
FuzzTarget (URL, param, method)
    │
    ▼
MutationEngine
    ├── SQL injection mutations (1000+ payloads)
    ├── XSS mutations (800+ payloads)
    ├── SSRF mutations (500+ payloads)
    ├── SSTI mutations (300+ payloads)
    ├── Path traversal (400+ patterns)
    └── Command injection (600+ payloads)
    │
    ▼
ExpertHeuristics
    ├── Technology-specific payload selection
    ├── WAF detection and bypass routing
    └── Context-aware injection points
    │
    ▼
ExploitChainEngine
    ├── SSRF → CSRF chain patterns
    ├── SQLi → file read chains
    ├── XSS → account takeover
    └── Zero-day discovery patterns
```

### Schemathesis (API Fuzzing)

When an OpenAPI/Swagger spec is available:

```bash
# Auto-discovered from /openapi.json, /swagger.json, /api/docs
schemathesis_fuzz url=https://example.com/openapi.json

# With auth
schemathesis_fuzz url=https://example.com/openapi.json auth="Bearer <token>"
```

Schemathesis generates test cases for **every documented endpoint**, checking for:
- HTTP 500 errors (crashes/unhandled exceptions)
- Schema validation failures
- Authentication bypass (missing/invalid auth)
- Authorization bypass (accessing other users' resources)

---

## Reporting

### Vulnerability Report Format

Reports are saved to `workspace/<target>/vulnerabilities/` as Markdown files:

```markdown
# SQL Injection in /api/v1/login

**Severity:** HIGH (CVSS 9.1)
**Type:** SQL Injection
**Endpoint:** POST /api/v1/login

## CVSS Vector
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Technical Analysis
[80+ character analysis required]

## Proof of Concept
import requests
response = requests.post("https://example.com/api/v1/login",
    data={"username": "admin'--", "password": "x"})
# Returns HTTP 200 with admin session — confirms SQLi

## Evidence
HTTP 200 OK — admin login bypassed

## Suggested Fix
# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s",
               (username, password))
```
### Validation Rules

| Field | Requirement |
|-------|-------------|
| `poc_script_code` | >50 characters, must contain real target URL |
| `poc_description` | Must include HTTP status evidence |
| `technical_analysis` | >80 characters |
| Language | Reports with "might", "possibly", "could" are rejected unless confirmed |

---

## Workspace Structure

All output is stored under `workspace/` in your current directory:

```
workspace/
└── <target>/
    ├── output/          # Raw tool outputs (.txt, .json, .xml, .nmap, ...)
    │   ├── subdomains.txt
    │   ├── live_hosts.txt
    │   ├── nmap_full.xml
    │   ├── httpx_output.json
    │   ├── nuclei_results.json
    │   └── katana_urls.txt
    ├── command/         # Command execution metadata and logs (.json)
    ├── tools/           # AI-generated Python/Bash exploit scripts
    │   ├── sqli_test.py
    │   └── ssrf_probe.sh
    └── vulnerabilities/ # Verified vulnerability reports (.md)
        ├── sql_injection_api_login.md
        ├── idor_user_profile_endpoint.md
        └── reflected_xss_search_parameter.md
```

---

## Troubleshooting

### "Ollama returned HTML error page" / server crashed

**Root cause:** Ollama ran out of VRAM and crashed. When this happens, its HTTP server returns an HTML error page instead of JSON — AIRecon cannot parse this and reports the error.

This is the most common error on long sessions or when running large models near VRAM limits.

**Why it happens:**
- KV cache (conversation history) grows with every iteration — a 500-iteration session uses 2–4× more VRAM than the initial model load
- `ollama_num_ctx: 65536` with a 32B model requires ~6–8 GB just for the KV cache, on top of model weights
- `run_parallel_agents` with multiple targets can double/triple VRAM usage simultaneously

**Fix in order of preference:**

```bash
# 1. Restart Ollama immediately (quick fix)
sudo systemctl restart ollama
```

```json
// 2. Reduce context window in ~/.airecon/config.json (permanent fix)
{
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384,
    "ollama_num_predict": 8192,
    "ollama_keep_alive": "10m"
}
```

**Recommended safe config for 16–20 GB VRAM:**
```json
{
    "ollama_model": "qwen3:32b",
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384,
    "ollama_num_predict": 8192,
    "ollama_keep_alive": "10m"
}
```

> Context compression runs every 15 iterations automatically — reducing `ollama_num_ctx` has minimal impact on long session quality.

### Ollama not responding

```bash
# Check Ollama is running
systemctl status ollama   # or
ollama serve &

# Verify model is available
ollama list

# Test connectivity
curl http://127.0.0.1:11434/api/tags
```

### Docker sandbox not starting

```bash
# Verify Docker daemon
docker ps

# Rebuild sandbox image manually
docker build -t airecon-sandbox airecon/containers/kali/

# Check for image
docker images | grep airecon
```

### Agent loops/stalls

Symptoms: Agent keeps calling the same tool, not making progress.

Solutions:
- Reduce `agent_repeat_tool_call_limit` to `1` to force variety
- Switch to a larger model (stalling often = reasoning failure)
- Reduce `ollama_num_ctx` if VRAM is exhausted (model degradation)
- Check `ollama_temperature`: values > 0.3 can cause looping

### PATH not found after install

```bash
# Add to ~/.zshrc or ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"
source ~/.zshrc
```

### Context window errors

If you see `context length exceeded` or very slow responses:

```json
{
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384
}
```

### Caido connection refused

Caido must be running before AIRecon connects. Default address: `127.0.0.1:48080`. If using a different port:

```json
{
    "caido_url": "http://127.0.0.1:8080"
}
```

---

## Documentation

- [Features](docs/features.md)
- [Configuration Reference](docs/configuration.md)
- [Installation Guide](docs/installation.md)
- [Tool Reference](docs/tools.md)
- [Adding Custom Skills](docs/development/creating_skills.md)

---

## License

MIT License. See `LICENSE` for details.

---

## Disclaimer

This tool is for **educational purposes and authorized security testing only**. Always obtain proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool.
