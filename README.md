<h1 align="center">
  <img src="images/logo.png" alt="AIRecon" width="200">
</h1>
<h4 align="center">AI-Powered Autonomous Penetration Testing Agent</h4>
<p align="center">
  <img src="https://img.shields.io/badge/language-python-green.svg">
  <img src="https://img.shields.io/badge/version-v0.1.6--beta-green.svg">
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

## Model Requirements

AIRecon requires a model with **extended thinking** (`<think>` blocks) and **reliable tool-calling**. Capabilities are auto-detected via `ollama show` metadata.

> **Minimum: 30B parameters.** Smaller models hallucinate tool output, invent CVEs, and skip scope rules.

| Model | Pull | VRAM | Notes |
|-------|------|------|-------|
| **Qwen3.5 122B** | `ollama pull qwen3.5:122b` | 48+ GB | Best quality |
| **Qwen3 32B** | `ollama pull qwen3:32b` | 20 GB | **Recommended minimum** |
| **Qwen3 30B-A3B** | `ollama pull qwen3:30b-a3b` | 16 GB | MoE — lower VRAM |

**Known issues:** DeepSeek R1 produces incomplete function calls. Models < 30B are unreliable for full recon.

---

## Installation

**Prerequisites:** Python 3.12+, Docker 20.10+, Ollama (running), git, curl

### One-line install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/pikpikcu/airecon/refs/heads/main/install.sh | bash
```

The script auto-detects remote vs local mode, installs Poetry if missing (via official installer — no system package conflicts), builds the wheel, and installs to `~/.local/bin`.

### Manual install (from source)

```bash
git clone https://github.com/pikpikcu/airecon.git
cd airecon
./install.sh
```

```bash
# Add to ~/.bashrc or ~/.zshrc if needed
export PATH="$HOME/.local/bin:$PATH"

airecon --version
```
---

## Configuration

Config file: `~/.airecon/config.json` (auto-generated on first run).

```json
{
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_model": "qwen3.5:122b",
    "ollama_timeout": 2400.0,
    "ollama_num_ctx": 131072,
    "ollama_num_ctx_small": 65536,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 32768,
    "ollama_keep_alive": "60m",
    "proxy_port": 3000,
    "command_timeout": 900.0,
    "docker_auto_build": true,
    "deep_recon_autostart": true,
    "agent_max_tool_iterations": 800,
    "allow_destructive_testing": false,
    "searxng_url": "http://localhost:8080",
    "vuln_similarity_threshold": 0.7
}
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
```json
{ "ollama_url": "http://192.168.1.100:11434", "ollama_model": "qwen3:32b" }
```

---

## Usage

```bash
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

```bash
sudo systemctl restart ollama
```

```json
// Reduce context for 16–20 GB VRAM setups
{ "ollama_num_ctx": 32768, "ollama_num_ctx_small": 16384, "ollama_num_predict": 8192 }
```

**Agent loops/stalls** — Usually a reasoning failure. Try a larger model, or reduce `ollama_temperature` to `< 0.2`.

**Docker sandbox not starting:**
```bash
docker build -t airecon-sandbox airecon/containers/kali/
```

**Caido connection refused** — Caido must be running before AIRecon. Default: `127.0.0.1:48080`.

**PATH not found after install:**
```bash
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

MIT License. See `LICENSE` for details.

---

## Disclaimer

AIRecon is built strictly for **educational purposes, ethical hacking, and authorized security assessments**. Any actions related to the material in this tool are solely your responsibility. Do not use this tool on systems or networks you do not own or have explicit permission to test.
