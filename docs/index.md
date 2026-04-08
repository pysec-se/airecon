# AIRecon

<div class="hero" markdown>

![AIRecon Logo](assets/logo.png)

# AIRecon

**AI-Assisted Penetration Testing Agent**

[![version](https://img.shields.io/badge/version-v0.1.7--beta-red.svg)](https://github.com/pikpikcu/airecon/releases)
[![python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![llm](https://img.shields.io/badge/LLM-Ollama%20(local)-orange.svg)](https://ollama.com/)
[![license](https://img.shields.io/badge/LICENSE-MIT-green.svg)](https://github.com/pikpikcu/airecon/blob/main/LICENSE)

</div>

---

AIRecon combines a self-hosted **Ollama LLM** with a **Kali Linux Docker sandbox**, native **Caido proxy integration**, a structured **RECON → ANALYSIS → EXPLOIT → REPORT pipeline**, and a real-time **Textual TUI**.

## Why AIRecon?

AIRecon is designed for local-first workflows where model execution and tool orchestration run in your own environment.

| Feature | AIRecon | Cloud-based agents |
|---------|---------|-------------------|
| API keys required | **No** | Yes |
| Target data sent to cloud | **No** | Yes |
| Works offline | **Yes** | No |
| Caido integration | **Native** | None |
| Session resume | **Yes** | Varies |
| VRAM/oom recovery | **Yes** | N/A |
| MCP support | **Built-in** | Varies |

---

## Core Features

<div class="feature-grid" markdown>

<div class="feature-card" markdown>
### Pipeline Engine
Structured 4-phase state machine: **RECON → ANALYSIS → EXPLOIT → REPORT**. Auto-transitions based on real findings, not iteration counts.
</div>

<div class="feature-card" markdown>
### Ollama Stability
Includes VRAM/OOM recovery paths, context monitoring, and conversation compression controls.
</div>

<div class="feature-card" markdown>
### Exploration Engine
Anti-stagnation with tool diversity tracking, same-tool streak detection, and per-phase exploration directives.
</div>

<div class="feature-card" markdown>
### Docker Sandbox
Kali Linux container with a curated recon/testing toolset. See the tools reference for the current catalog.
</div>

<div class="feature-card" markdown>
### Skills System
Built-in skill files are loaded on demand and can be extended with **[airecon-skills](https://github.com/pikpikcu/airecon-skills)**.
</div>

<div class="feature-card" markdown>
### Caido Integration
Built-in tools: list, replay, automate (`§FUZZ§`), findings, and scope. Default endpoint: `127.0.0.1:48080`.
</div>

<div class="feature-card" markdown>
### Browser Automation
Headless Chromium via Playwright, with session/cookie support and authentication helper flows.
</div>

<div class="feature-card" markdown>
### Session Memory
Findings and session state are persisted to disk. Sessions can be resumed with `airecon start --session <id>`.
</div>

<div class="feature-card" markdown>
### Security Controls
Includes command validation, symlink safety checks, CVE format validation, and session-save locking.
</div>

<div class="feature-card" markdown>
### Stability Focused
Config-based context limits, tool result truncation (50KB), incremental pruning, per-request timeouts, browser cleanup with force kill.
</div>

</div>

---

## Release Notes

See [Changelog](changelog.md) for versioned updates.


---

## Quick Start

### 1.  install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/pikpikcu/airecon/refs/heads/main/install.sh | bash
```
### 2. Start
```bash
airecon start
```

!!! tip "Model guidance"
    Use the largest model you can run reliably. AIRecon requires **native tool calling** support. Smaller models can work for limited tasks but are less reliable for long, autonomous runs.

!!! warning "Small models"
    Models below **8B** are not recommended for full engagements. Expect more tool-call errors and hallucinations as model size shrinks.

---

## Pipeline

<div class="pipeline-diagram">
  <pre><code>RECON ──────────────────────► ANALYSIS
  Enumerate attack surface       Identify injection points
  subfinder, nmap, katana,       semgrep, browser, httpx,
  httpx, ffuf, web_search        technology fingerprinting
         │                              │
         └──────────────────────────────┘
                                        │
                               EXPLOIT  ▼
                               Confirm vulnerabilities
                               quick_fuzz, advanced_fuzz,
                               sqlmap, dalfox, spawn_agent
                                        │
                               REPORT   ▼
                               Document all findings
                               create_vulnerability_report
  </code></pre>
</div>

Each phase has objectives, recommended tools, and transition criteria. Tool lists are examples; actual execution depends on scope and data. Phase enforcement is guidance-based and configurable.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](installation.md) | Hardware requirements, step-by-step setup, troubleshooting |
| [Configuration](configuration.md) | All config options with defaults, presets, and env var overrides |
| [Features](features.md) | Deep dive into every feature — pipeline, browser auth, fuzzing, skills, anti-context-loss |
| [Tools Reference](tools.md) | Complete reference for native tools and MCP tools |
| [Creating Skills](development/creating_skills.md) | Write your own skill files, use the airecon-skills community library |
| [Stability & Quality Status](stability.md) | Current validation snapshot, known blockers, and release-stability criteria |
| [Changelog](changelog.md) | Version history and release notes |

---

## Community

- **GitHub**: [github.com/pikpikcu/airecon](https://github.com/pikpikcu/airecon)
- **Skills Library**: [github.com/pikpikcu/airecon-skills](https://github.com/pikpikcu/airecon-skills)
- **Issues / Bug Reports**: [GitHub Issues](https://github.com/pikpikcu/airecon/issues)

---

!!! danger "Legal Disclaimer"
    AIRecon is built strictly for **educational purposes, ethical hacking, and authorized security assessments**. Any actions related to the material in this tool are solely your responsibility. **Do not use this tool on systems you do not own or have explicit permission to test.**
