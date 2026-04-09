<h1 align="center">
  <img src="images/logo.png" alt="AIRecon" width="200">
</h1>
<h4 align="center">AI-Powered Autonomous Penetration Testing Agent</h4>
<p align="center">
  <img src="https://img.shields.io/badge/language-python-green.svg">
  <img src="https://img.shields.io/badge/version-v0.1.7--beta-green.svg">
  <img src="https://img.shields.io/badge/python-3.12%2B-blue.svg">
  <img src="https://img.shields.io/badge/LLM-Ollama%20(local)-orange.svg">
  <a href="https://github.com/pikpikcu/airecon/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/LICENSE-MIT-red.svg">
  </a>
</p>

AIRecon is an autonomous penetration testing agent that combines a self-hosted **Ollama LLM** with a **Kali Linux Docker sandbox**, native **Caido proxy integration**, a structured **RECON → ANALYSIS → EXPLOIT → REPORT pipeline**, and a real-time **Textual TUI** — completely offline, no API keys required.

![Airecon](images/airecon.png)

---

## Why AIRecon?

Commercial API-based models (OpenAI GPT-4, Claude, Gemini) become prohibitively expensive for recursive, autonomous recon workflows that can require thousands of LLM calls per session.

AIRecon is built 100% for local, private operation.

| Feature | AIRecon | Cloud-based agents |
|---------|---------|-------------------|
| API keys required | **No** | Yes |
| Target data sent to cloud | **No** | Yes |
| Works offline | **Yes** | No |
| Caido integration | **Native** | None |
| Session resume | **Yes** | Varies |

- **Privacy First** — Target intelligence, tool output, and reports never leave your machine.
- **Caido Native** — 5 built-in tools: list, replay, automate (`§FUZZ§`), findings, scope.
- **Full Stack** — Kali sandbox + browser automation + custom fuzzer + Schemathesis API fuzzing + Semgrep SAST.
- **Skills Knowledge Base** — 57 built-in skill files, 289 keyword → skill auto-mappings. Extended by **[airecon-skills](https://github.com/pikpikcu/airecon-skills)** — a community skill library with 57 additional CLI-based playbooks for CTF, bug bounty, and pentesting.

---

## Pipeline

```
RECON → ANALYSIS → EXPLOIT → REPORT
```

Each phase has specific objectives, recommended tools, and automatic transition criteria. Phase enforcement is **soft** — the agent is guided but never blocked. Checkpoints run every 5 (phase eval), 10 (self-eval), and 15 (context compression) iterations.

---

## Memory & Learning (What It Actually Does)

AIRecon does **not** fine-tune the LLM. Its "learning" is local, structured telemetry that guides tool choice and avoids repeating failed paths.

**Local persistence (all on disk, no cloud):**
- SQLite memory DB at `~/.airecon/memory/airecon.db` storing sessions, findings, patterns, target intel, tool usage, model performance, skill usage, and attack-chain discoveries.
- Adaptive learning state at `~/.airecon/learning/global_learning.json` (tool performance stats, strategy patterns, observation log, distilled insights).
- Per-target memory files under `~/.airecon/memory/by_target/` when persisted, containing endpoints, vulns, WAF bypasses, sensitive params, and auth endpoints.
- Payload memory snapshots can be saved under `workspace/<target>/payload_memory.json` when session persistence runs.

**How it affects behavior:**
- On session start, memory context is injected (target intel, similar findings, learned patterns, tool reliability).
- Every 8 iterations, learned patterns and similar findings can be re-injected based on detected tech.
- Adaptive tool ranking uses historical success/failure to order tools and suggest strategies.
- Payload memory (when enabled) skips payloads that repeatedly failed for the same target/param.

---

## Model Requirements

AIRecon requires a model with **extended thinking** (`<think>` blocks) and **reliable tool-calling** capabilities. Capabilities are auto-detected via `ollama show` metadata.

> **⚠️ Tool calling support is REQUIRED.** The model must support native function/tool calling. Models without this capability will be unable to execute any tools (http_observe, execute, browser actions, etc.), making AIRecon completely non-functional.
> 
> **Recommended minimum: 8B-9B parameters.** Models below 8B are technically usable but strongly discouraged — they frequently hallucinate tool output, invent CVEs, skip scope rules, and produce unreliable tool calls.

| Model | Pull | VRAM | Notes |
|-------|------|------|-------|
| **Qwen3.5 122B** | `ollama pull qwen3.5:122b` | 48+ GB | Best quality, most reliable |
| **Qwen3.5 35B** | `ollama pull qwen3.5:35b` | 20 GB | **Recommended for most users** |
| **Qwen3.5 35b** | `ollama pull qwen3.5:35b-a3b` | 16 GB | MoE — lower VRAM |
| **Qwen3.5 9B** | `ollama pull qwen3.5:9b` | 6 GB | **Minimum viable** — expect frequent errors |

**Model size guidance:**
- **≥32B:** Reliable for full recon pipelines, good tool calling accuracy
- **8B-14B:** Usable for simple tasks, expect 20-40% tool call errors and hallucinations
- **<8B:** Technically works but produces unreliable results — not recommended for serious testing

**Known issues:** DeepSeek R1 produces incomplete function calls. Models < 8B lack reliable tool calling support.

---

## Installation

**Prerequisites:** Python 3.12+, Docker 20.10+, Ollama (running), git, curl

### One-line install (recommended)

```text
curl -fsSL https://raw.githubusercontent.com/pikpikcu/airecon/refs/heads/main/install.sh | bash
```

The script auto-detects remote vs local mode, installs Poetry if missing (via official installer — no system package conflicts), builds the wheel, and installs to `~/.local/bin`.

### Manual install (from source)

```text
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh
```

```text
# Add to ~/.bashrc or ~/.zshrc if needed
export PATH="$HOME/.local/bin:$PATH"

airecon --version
```
---

## Configuration

Config file: `~/.airecon/config.yaml` (auto-generated on first run). AIRecon will create `~/.airecon/` if it doesn't exist, including when a custom `~` path is used.

```yaml
# ======================================
# Ollama Connection
# ======================================
# Ollama API endpoint. REQUIRED — must be set. For local: http://127.0.0.1:11434. For remote: http://IP:11434
ollama_url: "http://127.0.0.1:11434"
# Model to use. 122B for best reasoning (requires 60GB+ VRAM). For 12GB VRAM: use qwen2.5:7b or smaller. For 8GB VRAM: use qwen2.5:1.8b.
ollama_model: "qwen3.5:122b"
# Total request timeout (seconds). 180s = 3 min. Stable for most models. Increase to 300s for slow remote servers or 122B models.
ollama_timeout: 180.0

# ======================================
# Ollama Model Settings
# ======================================
# Context window size. 65536 = 64K (stable for 12GB VRAM with 8B models). 131072 = 128K requires 30GB+ VRAM. Set -1 for server default.
ollama_num_ctx: 65536
# Context for CTF/summary mode. 32768 = 32K (stable for 12GB VRAM). Reduced from 64K for stability with 8B+ models.
ollama_num_ctx_small: 32768
# LLM output randomness. 0.0=deterministic, 0.15=recommended (strict), 0.3=creative. Does NOT affect thinking mode — controls output diversity only.
ollama_temperature: 0.15
# Max tokens to generate. 16384 = 16K (stable for 12GB VRAM). 32K requires more VRAM.
ollama_num_predict: 16384
# Enable extended thinking mode (for Qwen3.5+/Qwen2.5+). When enabled, model generates <think> reasoning blocks before answering.
ollama_enable_thinking: true
# Thinking intensity: low|medium|high|adaptive. For 12GB VRAM: use 'low' or 'medium'. 'high' may cause OOM with 8B models. Low=only deep tools, Medium=ANALYSIS+deep tools, High=most iterations (high VRAM only).
ollama_thinking_mode: low
# Protect first N tokens from KV eviction. 4096 = 4K (reduced for 12GB VRAM stability). 8K for larger VRAM.
ollama_num_keep: 4096

# ======================================
# Proxy Server
# ======================================
# Host to bind proxy server. 127.0.0.1 = localhost only.
proxy_host: 127.0.0.1
# Port for proxy server. Default 3000.
proxy_port: 3000

# ======================================
# Timeouts
# ======================================
# Docker command timeout (seconds). 900s = 15 min for long scans (nmap, nuclei).
command_timeout: 900.0

# ======================================
# Docker Sandbox
# ======================================
# Container memory limit. '16g' = 16GB (stable for 32GB+ RAM host, 18GB image + Chromium). Prevents OOM kills. Set to '12g' for 32GB RAM, '8g' for 16GB systems, '4g' for 8GB systems.
docker_memory_limit: 16g

# ======================================
# Deep Recon
# ======================================
# Auto-start deep recon on session start.
deep_recon_autostart: true
# Recon execution mode: standard|full. standard=respect user scope, full=auto-expand simple target prompts into comprehensive recon.
agent_recon_mode: standard

# ======================================
# Safety
# ======================================
# Allow destructive tests (e.g., DELETE requests). Default: False for safety.
allow_destructive_testing: false
```

| Key | Default | Notes |
|-----|---------|-------|
| `ollama_temperature` | `0.15` | Keep 0.1–0.2. Higher values cause hallucination. |
| `ollama_num_ctx` | `131072` | Reduce to `32768` if VRAM is limited. |
| `ollama_keep_alive` | `"60m"` | How long to keep model in VRAM. |
| `deep_recon_autostart` | `true` | Bare domain inputs auto-expand to full recon. |
| `allow_destructive_testing` | `false` | Unlocks aggressive modes (SQLi confirm, RCE chains). |
| `command_timeout` | `900.0` | Max seconds per shell command in Docker. |
| `vuln_similarity_threshold` | `0.7` | Jaccard dedup threshold for vulnerabilities. |

**Remote Ollama:**
```yaml
"ollama_url": "http://192.168.1.100:11434" 
"ollama_model": "qwen3:32b" 
```

---

## MCP Integration

AIRecon can connect to external MCP servers and expose their tools dynamically as `mcp_<server>` tools.

Config file: `~/.airecon/mcp.json`

**Example config:**
```json
{
  "mcpServers": {
    "hexstrike": {
      "command": "python3",
      "args": [
        "/path/hexstrike-ai/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "enabled": true
    },
    "xssgen": {
      "command": "python3",
      "args": [
        "/path/xssgen/xss_client.py",
        "--server",
        "http://127.0.0.1:8000"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "enabled": true
    },
    "recon": {
      "transport": "sse",
      "url": "https://example.com/mcp",
      "enabled": true,
      "headers": {
        "Authorization": "Bearer xxxxx"
      }
    }
  }
}   
```

**Using MCP tools in chat:**
- Tool name format: `mcp_<server>`
- Actions: `list_tools`, `search_tools`, `call_tool`

Example:
```json
{"name": "mcp_acme", "arguments": {"action": "list_tools"}}
```

---

## Usage

```text
airecon start                          # start TUI
airecon start --session <session_id>  # resume session
```

**Example prompts:**

```
# Full pipeline
full recon on example.com
pentest https://api.example.com

# Specific tasks
find subdomains of example.com
scan ports on 10.0.0.1
check for XSS on https://example.com/search
test SQL injection on https://example.com/api/login parameter: username
run schemathesis on https://example.com/openapi.json

# Authenticated testing
login to https://example.com/login with admin@example.com / password123 then test for IDOR
test https://app.example.com with TOTP: JBSWY3DPEHPK3PXP

# Multi-agent
spawn an XSS specialist on https://example.com/search
run parallel recon on: example.com, sub.example.com, api.example.com

# Caido
replay request #1234 with a modified Authorization header
use Caido to fuzz the username parameter in request #45 with §FUZZ§ markers
```

---

## Workspace

```
workspace/<target>/
├── output/          # Raw tool outputs (nmap, httpx, nuclei, subfinder, ...)
├── tools/           # AI-generated exploit scripts (.py, .sh)
└── vulnerabilities/ # Verified vulnerability reports (.md)
```

Sessions persist at `~/.airecon/sessions/<session_id>.json` — subdomains, ports, technologies, URLs, vulnerabilities (Jaccard dedup), auth tokens, and completed phases.

---

## Troubleshooting

**Ollama OOM / HTML error page** — Most common on long sessions or large models near VRAM limits.

```text
sudo systemctl restart ollama
```

```json
{ "ollama_num_ctx": 32768, "ollama_num_ctx_small": 16384, "ollama_num_predict": 8192 }
```

**Agent loops/stalls** — Usually a reasoning failure. Try a larger model, or reduce `ollama_temperature` to `< 0.2`.

**Docker sandbox not starting:**
```text
docker build -t airecon-sandbox airecon/containers/kali/
```

**Caido connection refused** — Caido must be running before AIRecon. Default: `127.0.0.1:48080`.

**PATH not found after install:**
```text
export PATH="$HOME/.local/bin:$PATH" && source ~/.zshrc
```

---

## Documentation

- [Features](docs/features.md)
- [Configuration Reference](docs/configuration.md)
- [Tool Reference](docs/tools.md)
- [Adding Custom Skills](docs/development/creating_skills.md)

---

## License

MIT License. See [`LICENSE`](LICENSE) for details.

---