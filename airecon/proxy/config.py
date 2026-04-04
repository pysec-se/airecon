from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("airecon.proxy.config")

APP_DIR_NAME = ".airecon"
CONFIG_FILENAME = "config.yaml"

_CONFIG_SCHEMA: dict[str, tuple[Any, str]] = {
    "ollama_url": (
        "http://127.0.0.1:11434",
        "Ollama API endpoint. For remote servers use http://IP:11434",
    ),
    "ollama_model": (
        "qwen3.5:122b",
        "Model to use. 122B for best reasoning (requires 60GB+ VRAM). For 12GB VRAM: use qwen2.5:7b or smaller. For 8GB VRAM: use qwen2.5:1.8b.",
    ),
    "ollama_timeout": (
        180.0,
        "Total request timeout (seconds). 180s = 3 min. Stable for most models. Increase to 300s for slow remote servers or 122B models.",
    ),
    "ollama_chunk_timeout": (
        180.0,
        "Per-chunk stream timeout (seconds). 180s stable for most models. Increase to 240s for 122B model prefill over network or slow connections.",
    ),
    "ollama_num_ctx": (
        65536,
        "Context window size. 65536 = 64K (stable for 12GB VRAM with 8B models). 131072 = 128K requires 30GB+ VRAM. Set -1 for server default.",
    ),
    "ollama_num_ctx_small": (
        32768,
        "Context for CTF/summary mode. 32768 = 32K (stable for 12GB VRAM). Reduced from 64K for stability with 8B+ models.",
    ),
    "ollama_temperature": (
        0.15,
        "LLM output randomness. 0.0=deterministic, 0.15=recommended (strict), 0.3=creative. Does NOT affect thinking mode — controls output diversity only.",
    ),
    "ollama_num_predict": (
        16384,
        "Max tokens to generate. 16384 = 16K (stable for 12GB VRAM). 32K requires more VRAM.",
    ),
    "ollama_enable_thinking": (
        True,
        "Enable extended thinking mode (for Qwen3.5+/Qwen2.5+). When enabled, model generates <think> reasoning blocks before answering.",
    ),
    "ollama_thinking_mode": (
        "low",
        "Thinking intensity: low|medium|high|adaptive. For 12GB VRAM: use 'low' or 'medium'. 'high' may cause OOM with 8B models. Low=only deep tools, Medium=ANALYSIS+deep tools, High=most iterations (high VRAM only).",
    ),
    "ollama_supports_thinking": (
        True,
        "Auto-detected: model supports <think> blocks. Set false for older models without thinking support.",
    ),
    "ollama_supports_native_tools": (
        True,
        "Auto-detected: model supports native tool calling. Set false for models without tool-calling capability.",
    ),
    "ollama_max_concurrent_requests": (
        1,
        "Max concurrent Ollama requests. Keep 1 for 8B+ models to prevent OOM. For 122B: MUST be 1.",
    ),
    "ollama_num_keep": (
        4096,
        "Protect first N tokens from KV eviction. 4096 = 4K (reduced for 12GB VRAM stability). 8K for larger VRAM.",
    ),
    "ollama_repeat_penalty": (
        1.05,
        "Prevent repetition loops. 1.05 = mild. Range: 1.0–1.2.",
    ),
    "proxy_host": (
        "127.0.0.1",
        "Host to bind proxy server. 127.0.0.1 = localhost only.",
    ),
    "proxy_port": (3000, "Port for proxy server. Default 3000."),
    "command_timeout": (
        900.0,
        "Docker command timeout (seconds). 900s = 15 min for long scans (nmap, nuclei).",
    ),
    "docker_image": ("airecon-sandbox", "Docker image name for sandbox container."),
    "docker_auto_build": (True, "Auto-build Docker image on startup if not exists."),
    "docker_memory_limit": (
        "16g",
        "Container memory limit. '16g' = 16GB (stable for 32GB+ RAM host, 18GB image + Chromium). Prevents OOM kills. Set to '12g' for 32GB RAM, '8g' for 16GB systems, '4g' for 8GB systems.",
    ),
    "tool_response_role": (
        "tool",
        "Role for tool responses in conversation. Keep 'tool'.",
    ),
    "deep_recon_autostart": (True, "Auto-start deep recon on session start."),
    "agent_recon_mode": (
        "standard",
        "Recon execution mode: standard|full. standard=respect user scope, full=auto-expand simple target prompts into comprehensive recon.",
    ),
    "agent_max_tool_iterations": (
        600,
        "Max tool calls per session. 600 for 12GB VRAM stability. 1200 for 32GB+ VRAM systems. For 8B models: 600 is stable.",
    ),
    "agent_repeat_tool_call_limit": (
        2,
        "Max times to repeat same tool call. 2 = retry once.",
    ),
    "agent_missing_tool_retry_limit": (
        2,
        "Max retries for missing tool. 2 = retry once.",
    ),
    "agent_plan_revision_interval": (
        20,
        "Revise attack plan every N iterations. 20 for 12GB VRAM (more frequent resets). 30 for larger VRAM.",
    ),
    "agent_exploration_mode": (
        True,
        "Enable exploration mode (broader scanning). For 8B models: consider setting to False.",
    ),
    "agent_exploration_intensity": (
        0.7,
        "Exploration aggressiveness. 0.7 for 12GB VRAM (reduced from 0.9). 0.9 for larger VRAM. Range: 0.5–1.0.",
    ),
    "agent_exploration_temperature": (
        0.3,
        "Temperature for exploration. 0.3 for 12GB VRAM (lower for stability). 0.5 for larger VRAM.",
    ),
    "agent_stagnation_threshold": (
        3,
        "Iterations without progress before forcing new approach. 3 for 12GB VRAM (more patient).",
    ),
    "agent_tool_diversity_window": (
        6,
        "Window for tool diversity check. 6 for 12GB VRAM (more aggressive tool switching).",
    ),
    "agent_max_same_tool_streak": (
        2,
        "Max consecutive same tool calls. 2 for 12GB VRAM (force switch after 2 identical calls). 3 for larger VRAM.",
    ),
    "agent_phase_creative_temperature": (
        0.15,
        "Temperature for ANALYSIS/EXPLOIT phases. 0.15 for 12GB VRAM (more deterministic). 0.20 for larger VRAM.",
    ),
    "allow_destructive_testing": (
        False,
        "Allow destructive tests (e.g., DELETE requests). Default: False for safety.",
    ),
    "browser_page_load_delay": (
        1.0,
        "Delay after page load (seconds). 1.0s for JS-heavy sites.",
    ),
    "browser_action_timeout": (
        45,
        "Browser action timeout (seconds). 45s for standard recon (faster recovery).",
    ),
    "ollama_keep_alive": (
        -1,
        "How long to keep model in VRAM. -1 = forever, '60m' = 60 min, 0 = unload immediately.",
    ),
    "searxng_url": (
        "http://localhost:8080",
        "SearXNG instance URL. Leave default for local auto-managed instance.",
    ),
    "searxng_engines": (
        "google,bing,duckduckgo,brave,google_news,github,stackoverflow",
        "Comma-separated search engines.",
    ),
    "vuln_similarity_threshold": (
        0.7,
        "Vulnerability dedup threshold. 0.7 = 70% similarity = duplicate. Range: 0.5–0.9.",
    ),
    "evidence_similarity_threshold": (
        0.70,
        "Evidence dedup threshold. 0.70 = 70% similarity = duplicate. Range: 0.5–0.9.",
    ),
    "pipeline_recon_min_subdomains": (
        3,
        "Min subdomains before RECON→ANALYSIS. 3 = at least 3 subdomains.",
    ),
    "pipeline_recon_min_urls": (
        1,
        "Min URLs before RECON→ANALYSIS. 1 = at least 1 URL.",
    ),
    "pipeline_recon_soft_timeout": (
        30,
        "Force RECON→ANALYSIS after N iterations. 30 = force after 30 iterations.",
    ),
    "agent_max_conversation_messages": (
        None,
        "Max messages in conversation. Auto-calculated from ollama_num_ctx // 256 for 12GB VRAM stability (was //128).",
    ),
    "agent_compression_trigger_ratio": (
        0.7,
        "Compress at X% of max messages. 0.7 = compress at 70% (more aggressive for 12GB VRAM). 0.8 for larger VRAM.",
    ),
    "agent_uncompressed_keep_count": (
        10,
        "Keep last N messages uncompressed. 10 for 12GB VRAM (reduced from 20). 20 for larger VRAM.",
    ),
    "agent_llm_compression_num_ctx": (
        4096,
        "Context window for LLM compression. 4096 = 4K (reduced from 8K for 12GB VRAM stability).",
    ),
    "agent_llm_compression_num_predict": (
        512,
        "Output tokens for compression. 512 = more concise summaries (reduced from 1024 for stability).",
    ),
    "agent_context_reset_cooldown_seconds": (
        45,
        "Minimum seconds between forced Ollama context resets. 45s for 12GB VRAM (faster than 60s). 300s for regular recon on large VRAM.",
    ),
}

DEFAULT_CONFIG = {key: value for key, (value, _) in _CONFIG_SCHEMA.items()}

_CONFIG_CATEGORIES = [
    (
        "Ollama Connection",
        ["ollama_url", "ollama_model", "ollama_timeout", "ollama_chunk_timeout"],
    ),
    (
        "Ollama Model Settings",
        [
            "ollama_num_ctx",
            "ollama_num_ctx_small",
            "ollama_temperature",
            "ollama_num_predict",
            "ollama_enable_thinking",
            "ollama_thinking_mode",
            "ollama_supports_thinking",
            "ollama_supports_native_tools",
            "ollama_max_concurrent_requests",
            "ollama_num_keep",
            "ollama_repeat_penalty",
        ],
    ),
    ("Proxy Server", ["proxy_host", "proxy_port"]),
    ("Timeouts", ["command_timeout"]),
    ("Docker Sandbox", ["docker_image", "docker_auto_build", "docker_memory_limit"]),
    ("Tool Behavior", ["tool_response_role"]),
    ("Deep Recon", ["deep_recon_autostart", "agent_recon_mode"]),
    (
        "Agent Loop Controls",
        [
            "agent_max_tool_iterations",
            "agent_repeat_tool_call_limit",
            "agent_missing_tool_retry_limit",
            "agent_plan_revision_interval",
            "agent_exploration_mode",
            "agent_exploration_intensity",
            "agent_exploration_temperature",
            "agent_stagnation_threshold",
            "agent_tool_diversity_window",
            "agent_max_same_tool_streak",
            "agent_phase_creative_temperature",
        ],
    ),
    ("Safety", ["allow_destructive_testing"]),
    ("Browser", ["browser_page_load_delay", "browser_action_timeout"]),
    ("Ollama Keep-Alive", ["ollama_keep_alive"]),
    ("SearXNG", ["searxng_url", "searxng_engines"]),
    ("Deduplication", ["vuln_similarity_threshold", "evidence_similarity_threshold"]),
    (
        "Phase Transitions",
        [
            "pipeline_recon_min_subdomains",
            "pipeline_recon_min_urls",
            "pipeline_recon_soft_timeout",
        ],
    ),
    (
        "Context Management",
        [
            "agent_max_conversation_messages",
            "agent_compression_trigger_ratio",
            "agent_uncompressed_keep_count",
            "agent_llm_compression_num_ctx",
            "agent_llm_compression_num_predict",
            "agent_context_reset_cooldown_seconds",
        ],
    ),
]

_workspace_root_cache: Path | None = None
_workspace_root_lock = threading.Lock()

_config_reload_lock: asyncio.Lock | None = None


def get_workspace_root() -> Path:
    global _workspace_root_cache
    if _workspace_root_cache is None:
        with _workspace_root_lock:
            if _workspace_root_cache is None:
                _workspace_root_cache = Path.cwd() / "workspace"
                _workspace_root_cache.mkdir(parents=True, exist_ok=True)
    return _workspace_root_cache


def _write_yaml_with_comments(config: dict, filepath: Path) -> None:
    from airecon._version import __version__

    lines = []

    lines.append("#╔══════════════════════════════════════════════════════════╗")
    lines.append("#║              AIRecon Configuration File                  ║")
    lines.append("#║                                                          ║")
    lines.append(f"#║  Version: {__version__:<46} ║")
    lines.append("#║  Format: YAML (supports comments)                        ║")
    lines.append("#║  Edit this file to customize AIRecon behavior            ║")
    lines.append("#║                                                          ║")
    lines.append("#║  Docs: https://github.com/pikpikcu/airecon               ║")
    lines.append("#╚══════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append("# Quick Start:")
    lines.append("#   1. Check your VRAM and set appropriate model:")
    lines.append("#      - 12GB VRAM: qwen2.5:7b or qwen2.5:1.8b (stable)")
    lines.append("#      - 16GB VRAM: qwen2.5:14b or qwen3.5:32b")
    lines.append("#      - 24GB+ VRAM: qwen3.5:70b")
    lines.append("#      - 60GB+ VRAM: qwen3.5:122b")
    lines.append("#   2. Context sizes (VRAM requirements):")
    lines.append("#      - 32K (32768): 8GB VRAM stable (CTF mode)")
    lines.append("#      - 64K (65536): 12GB VRAM stable (standard mode)")
    lines.append("#      - 128K (131072): 30GB+ VRAM required")
    lines.append("#   3. Set ollama_url for remote Ollama servers")
    lines.append("#   4. Run: airecon start")
    lines.append("")

    for category, keys in _CONFIG_CATEGORIES:
        lines.append("")
        lines.append(f"# {'=' * 38}")
        lines.append(f"# {category}")
        lines.append(f"# {'=' * 38}")

        for key in keys:
            if key in config:
                value = config[key]
                comment = _CONFIG_SCHEMA.get(key, ("", ""))[1]

                if isinstance(value, str):
                    if value.startswith("http") or ":" in value or value == "":
                        value_str = f'"{value}"'
                    else:
                        value_str = value
                elif isinstance(value, bool):
                    value_str = "true" if value else "false"
                elif value is None:
                    value_str = "null"
                elif isinstance(value, float):
                    value_str = str(value)
                else:
                    value_str = str(value)

                if comment:
                    lines.append(f"# {comment}")
                lines.append(f"{key}: {value_str}")

    with open(filepath, "w") as f:
        f.write("\n".join(lines) + "\n")


@dataclass(frozen=True)
class Config:
    ollama_url: str
    ollama_model: str

    proxy_host: str
    proxy_port: int

    ollama_timeout: float
    ollama_chunk_timeout: float
    command_timeout: float

    ollama_num_ctx: int
    ollama_num_ctx_small: int
    ollama_temperature: float
    ollama_num_predict: int
    ollama_enable_thinking: bool
    ollama_thinking_mode: str
    ollama_supports_thinking: bool
    ollama_supports_native_tools: bool
    ollama_max_concurrent_requests: int
    ollama_num_keep: int
    ollama_repeat_penalty: float

    docker_image: str
    docker_auto_build: bool
    docker_memory_limit: str

    tool_response_role: str

    deep_recon_autostart: bool
    agent_recon_mode: str

    agent_max_tool_iterations: int
    agent_repeat_tool_call_limit: int
    agent_missing_tool_retry_limit: int
    agent_plan_revision_interval: int
    agent_exploration_mode: bool
    agent_exploration_intensity: float
    agent_exploration_temperature: float
    agent_stagnation_threshold: int
    agent_tool_diversity_window: int
    agent_max_same_tool_streak: int
    agent_phase_creative_temperature: float

    allow_destructive_testing: bool

    browser_page_load_delay: float

    browser_action_timeout: int

    ollama_keep_alive: int | str

    searxng_url: str
    searxng_engines: str

    vuln_similarity_threshold: float

    evidence_similarity_threshold: float

    pipeline_recon_min_subdomains: int
    pipeline_recon_min_urls: int
    pipeline_recon_soft_timeout: int

    agent_max_conversation_messages: int
    agent_compression_trigger_ratio: float
    agent_uncompressed_keep_count: int
    agent_llm_compression_num_ctx: int
    agent_llm_compression_num_predict: int
    agent_context_reset_cooldown_seconds: int

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        if config_path:
            config_file = Path(config_path)
        else:
            home_dir = Path.home()
            config_dir = home_dir / APP_DIR_NAME
            config_file = config_dir / CONFIG_FILENAME

            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)

        current_config: dict[str, Any] = {}
        user_config: dict[str, Any] = {}

        if config_file.exists():
            try:
                with open(config_file, "r") as f:
                    loaded = yaml.safe_load(f)
                    if loaded is None:
                        logger.warning(
                            "Config file %s is empty (got None). Rewriting with defaults.",
                            config_file,
                        )
                        _write_yaml_with_comments(DEFAULT_CONFIG, config_file)
                        logger.info("Config file reset to defaults at %s", config_file)
                    elif isinstance(loaded, dict):
                        user_config = loaded
                    else:
                        logger.error(
                            "Config file %s is corrupt (expected YAML mapping, got %s). "
                            "Rewriting with defaults.",
                            config_file,
                            type(loaded).__name__,
                        )
                        _write_yaml_with_comments(DEFAULT_CONFIG, config_file)
                        logger.info("Config file reset to defaults at %s", config_file)
                    current_config.update(user_config)
            except Exception as e:
                logger.error(
                    "Failed to load config from %s: %s. "
                    "Resetting to defaults and rewriting config file.",
                    config_file,
                    e,
                )

                try:
                    _write_yaml_with_comments(DEFAULT_CONFIG, config_file)
                    logger.info("Config file reset to defaults at %s", config_file)
                except Exception as write_err:
                    logger.error("Could not rewrite config file: %s", write_err)
        else:
            if config_path is None:
                logger.info(
                    f"No config found. Generating default config at {config_file}"
                )
                try:
                    _write_yaml_with_comments(DEFAULT_CONFIG, config_file)
                    logger.info(
                        f"Generated config file: {config_file}\n"
                        f"Edit this file to customize AIRecon. Comments included!"
                    )
                except Exception as e:
                    logger.error("Failed to write default config: %s", e)
            else:
                logger.warning(
                    f"Configuration file not found at {config_file}. Using default configuration settings."
                )

        for key in DEFAULT_CONFIG:
            env_key = f"AIRECON_{key.upper()}"
            if env_key in os.environ:
                val = os.environ[env_key]
                default_val = DEFAULT_CONFIG.get(key)
                if isinstance(default_val, bool):
                    current_config[key] = val.lower() in ("true", "1", "yes")
                elif isinstance(default_val, int):
                    try:
                        current_config[key] = int(val)
                    except (ValueError, TypeError):
                        logger.warning(
                            "AIRECON_%s env var %r is not a valid int — ignored",
                            key.upper(),
                            val,
                        )
                elif isinstance(default_val, float):
                    try:
                        current_config[key] = float(val)
                    except (ValueError, TypeError):
                        logger.warning(
                            "AIRECON_%s env var %r is not a valid float — ignored",
                            key.upper(),
                            val,
                        )
                else:
                    current_config[key] = val

        explicit_cap = "AIRECON_AGENT_MAX_CONVERSATION_MESSAGES" in os.environ
        if not explicit_cap and "agent_max_conversation_messages" in current_config:
            configured_cap = current_config.get("agent_max_conversation_messages")
            explicit_cap = (
                configured_cap != DEFAULT_CONFIG["agent_max_conversation_messages"]
            )
        if not explicit_cap:
            current_config["agent_max_conversation_messages"] = None

        return cls.load_with_defaults(current_config)

    @classmethod
    def load_with_defaults(cls, raw: dict) -> Config:
        known_fields = {f.name for f in dataclasses.fields(cls)}
        merged = {k: DEFAULT_CONFIG[k] for k in known_fields if k in DEFAULT_CONFIG}
        merged.update({k: v for k, v in raw.items() if k in known_fields})
        unknown = set(raw) - known_fields
        if unknown:
            logger.warning(
                "Config: ignoring unknown fields (possibly from an older config): %s",
                ", ".join(sorted(unknown)),
            )

        for key in list(merged):
            default_val = DEFAULT_CONFIG.get(key)
            if default_val is None:
                continue
            expected_type = type(default_val)
            val = merged[key]
            if key == "agent_max_conversation_messages" and val is None:
                continue
            if not isinstance(val, expected_type):
                try:
                    if expected_type is bool:
                        if isinstance(val, str):
                            merged[key] = val.lower() in ("true", "1", "yes")
                        else:
                            merged[key] = bool(val)
                    else:
                        merged[key] = expected_type(val)
                    logger.warning(
                        "Config: coerced '%s' from %s to %s",
                        key,
                        type(val).__name__,
                        expected_type.__name__,
                    )
                except (ValueError, TypeError):
                    logger.warning(
                        "Config: could not coerce '%s' value %r to %s — using default %r",
                        key,
                        val,
                        expected_type.__name__,
                        default_val,
                    )
                    merged[key] = default_val

        _BOUNDS_RULES: dict[str, tuple[float | None, float | None]] = {
            "vuln_similarity_threshold": (0.0, 1.0),
            "evidence_similarity_threshold": (0.0, 1.0),
            "ollama_timeout": (10.0, 86400.0),
            "ollama_chunk_timeout": (10.0, 3600.0),
            "command_timeout": (10.0, 86400.0),
            "browser_action_timeout": (10, 600),
            "agent_max_tool_iterations": (50, 5000),
            "agent_repeat_tool_call_limit": (1, 10),
            "agent_missing_tool_retry_limit": (0, 10),
            "agent_plan_revision_interval": (5, 300),
            "agent_stagnation_threshold": (1, 20),
            "agent_tool_diversity_window": (3, 50),
            "agent_max_same_tool_streak": (1, 20),
            "agent_phase_creative_temperature": (0.0, 1.0),
            "agent_exploration_intensity": (0.0, 1.0),
            "agent_exploration_temperature": (0.0, 2.0),
            "ollama_num_ctx": (-1, 10000000),
            "ollama_num_ctx_small": (512, 5000000),
            "ollama_num_predict": (1, 262144),
            "ollama_max_concurrent_requests": (1, 10),
            "ollama_num_keep": (0, 5000000),
            "ollama_repeat_penalty": (1.0, 2.0),
            "agent_max_conversation_messages": (50, 20000),
            "agent_compression_trigger_ratio": (0.5, 0.95),
            "agent_uncompressed_keep_count": (5, 200),
            "agent_llm_compression_num_ctx": (1024, 32768),
            "agent_llm_compression_num_predict": (256, 8192),
            "agent_context_reset_cooldown_seconds": (0, 86400),
            "browser_page_load_delay": (0.0, 30.0),
            "pipeline_recon_min_subdomains": (0, 1000),
            "pipeline_recon_min_urls": (0, 10000),
            "pipeline_recon_soft_timeout": (5, 1000),
        }

        for bkey, (lo, hi) in _BOUNDS_RULES.items():
            bval = merged.get(bkey)
            if bval is None:
                continue

            if bkey == "ollama_num_ctx" and bval == -1:
                logger.info(
                    "Config: ollama_num_ctx=-1 (unlimited) — using Ollama server default"
                )
                continue

            out_of_range = (lo is not None and bval < lo) or (
                hi is not None and bval > hi
            )

            if out_of_range:
                default_bval = DEFAULT_CONFIG.get(bkey)
                if default_bval is None:
                    default_bval = lo

                logger.warning(
                    "Config: '%s' value %r is out of allowed range [%s, %s] — using default %r",
                    bkey,
                    bval,
                    lo,
                    hi,
                    default_bval,
                )
                merged[bkey] = default_bval

        if merged.get("agent_max_conversation_messages") is None:
            try:
                ctx_val = int(
                    merged.get("ollama_num_ctx", DEFAULT_CONFIG["ollama_num_ctx"])
                )
            except (TypeError, ValueError):
                ctx_val = int(DEFAULT_CONFIG["ollama_num_ctx"])
            merged["agent_max_conversation_messages"] = max(
                100, min(10000, ctx_val // 128)
            )

        recon_mode = str(merged.get("agent_recon_mode", "standard")).strip().lower()
        if recon_mode not in {"standard", "full"}:
            logger.warning(
                "Config: 'agent_recon_mode' value %r is invalid — using default %r",
                merged.get("agent_recon_mode"),
                DEFAULT_CONFIG["agent_recon_mode"],
            )
            recon_mode = str(DEFAULT_CONFIG["agent_recon_mode"])
        merged["agent_recon_mode"] = recon_mode

        return cls(**merged)


_config: Config | None = None
_config_mtime: float = 0.0
_config_path: Path | None = None
_config_init_lock = threading.Lock()


def _get_config_path(config_path: str | Path | None = None) -> Path:
    if config_path:
        return Path(config_path)
    return Path.home() / APP_DIR_NAME / CONFIG_FILENAME


def get_config(config_path: str | None = None) -> Config:
    global _config, _config_mtime, _config_path

    if _config_path is None:
        _config_path = _get_config_path(config_path)

    if _config is not None:
        try:
            current_mtime = (
                _config_path.stat().st_mtime if _config_path.exists() else 0.0
            )
            if current_mtime > _config_mtime:
                try:
                    asyncio.get_running_loop()

                    global _config_reload_lock
                    if _config_reload_lock is None:
                        _config_reload_lock = asyncio.Lock()

                except RuntimeError:
                    pass

                logger.info("Config file changed — reloading from %s", _config_path)
                with _config_init_lock:
                    _config = Config.load(_config_path)
                    _config_mtime = current_mtime
        except Exception as e:
            logger.debug("Expected failure in config reload check: %s", e)

    if _config is None:
        with _config_init_lock:
            if _config is None:
                _config = Config.load(config_path)
                try:
                    _config_mtime = (
                        _config_path.stat().st_mtime if _config_path.exists() else 0.0
                    )
                except Exception:
                    _config_mtime = 0.0

    return _config


async def get_config_async(config_path: str | None = None) -> Config:
    global _config, _config_mtime, _config_path, _config_reload_lock

    if _config_path is None:
        _config_path = _get_config_path(config_path)

    if _config_reload_lock is None:
        _config_reload_lock = asyncio.Lock()

    async with _config_reload_lock:
        if _config is not None:
            try:
                current_mtime = (
                    _config_path.stat().st_mtime if _config_path.exists() else 0.0
                )
                if current_mtime > _config_mtime:
                    logger.info("Config file changed — reloading from %s", _config_path)
                    _config = Config.load(_config_path)
                    _config_mtime = current_mtime
            except Exception:
                pass

        if _config is None:
            _config = Config.load(config_path)
            try:
                _config_mtime = (
                    _config_path.stat().st_mtime if _config_path.exists() else 0.0
                )
            except Exception:
                _config_mtime = 0.0

    return _config


def reload_config() -> Config:
    global _config, _config_mtime
    _config = None
    _config_mtime = 0.0
    return get_config()
