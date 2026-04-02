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

| Feature | AIRecon | Cloud-based agents |\n|---------|---------|-------------------|\n| API keys required | **No** | Yes |\n| Target data sent to cloud | **No** | Yes |\n| Works offline | **Yes** | No |\n| Caido integration | **Native** | None |\n| Session resume | **Yes** | Varies |\n| VRAM crash recovery | **4-tier auto** | N/A |\n| MCP support | **Built-in** | None |

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
Anti-stagnation with temperature boost, tool diversity tracking, same-tool streak detection, per-phase exploration directives.
</div>

<div class="feature-card" markdown>
### Docker Sandbox
Kali Linux container with preinstalled recon and testing tools (for example: subfinder, nuclei, sqlmap, dalfox, ffuf, semgrep, and Playwright).
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

## Recent Improvements (v0.1.7-beta)

### MCP Improvements
- ✅ MCP server list now surfaces total tool counts (`total_tools`) when available
- ✅ `/mcp list <name>` keeps output lightweight by showing only the first 10 tools
- ✅ Better MCP display consistency for large toolsets (for example 150+ tools)

### TUI & UX
- ✅ Confirm-delete modal styling centralized in `styles.tcss`
- ✅ Status bar rendering restored using widget-local CSS to avoid global style conflicts

### Stability & Tests
- ✅ `/api/status` degraded-state logic fixed for explicit Ollama-down results
- ✅ Full test suite green after fixes: `1608 passed`
- ⚠️ Interactive CAPTCHA/TOTP verification remains user-led before production promotion.


---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh

# 2. Pull a model (minimum 30B parameters)
ollama pull qwen3:32b

# 3. Start
airecon start
```

!!! tip "Recommended model"
    **qwen3:32b** (20 GB VRAM) is a practical minimum. **qwen3.5:122b** (48+ GB VRAM) generally performs better on long, complex runs.

!!! warning "Minimum model size"
    Models below **30B parameters** frequently hallucinate tool output, ignore scope rules, and produce incomplete function calls. `qwen3:14b` is **not recommended** for real engagements.

---

## Pipeline

```
RECON ──────────────────────► ANALYSIS
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
```

Each phase has specific objectives, recommended tools, and transition criteria. Phase enforcement is guidance-based, not strict hard-blocking.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](installation.md) | Hardware requirements, step-by-step setup, troubleshooting |
| [Configuration](configuration.md) | All config options with defaults, presets, and env var overrides |
| [Features](features.md) | Deep dive into every feature — pipeline, browser auth, fuzzing, skills, anti-context-loss |
| [Tools Reference](tools.md) | Complete reference for all 31 native tools |
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
