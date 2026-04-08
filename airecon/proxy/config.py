from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import threading
import tempfile
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
        "Ollama API endpoint. REQUIRED — must be set. For local: http://127.0.0.1:11434. For remote: http://IP:11434",
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
        120,
        "Browser action timeout (seconds). 120s for modern heavy pages.",
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
    "caido_graphql_url": (
        "http://127.0.0.1:48080/graphql",
        "Caido GraphQL API endpoint. Change if Caido runs on different host/port.",
    ),
    "browser_cdp_port": (
        9222,
        "Chrome DevTools Protocol debug port. Default 9222.",
    ),
    "browser_cdp_bind_address": (
        "0.0.0.0",  # nosec B104: Security testing tool intentionally binds to all interfaces
        "Chrome remote debugging bind address. 0.0.0.0 = all interfaces, 127.0.0.1 = localhost only.",
    ),
    "browser_connect_timeout_ms": (
        3000,
        "Playwright browser connect timeout in milliseconds.",
    ),
    "browser_navigation_timeout_ms": (
        60000,
        "Browser page navigation timeout in milliseconds.",
    ),
    "browser_login_form_wait_ms": (
        8000,
        "Browser wait time for login form rendering in milliseconds.",
    ),
    "browser_page_load_timeout_ms": (
        10000,
        "Browser page load timeout in milliseconds.",
    ),
    "browser_oauth_callback_timeout_ms": (
        15000,
        "Browser OAuth callback wait timeout in milliseconds.",
    ),
    "browser_totp_fill_timeout_ms": (
        3000,
        "Browser TOTP field fill timeout in milliseconds.",
    ),
    "browser_screenshot_timeout_ms": (
        5000,
        "Browser screenshot capture timeout in milliseconds.",
    ),
    # captcha_ollama_model removed — uses ollama_model instead (qwen3.5 supports vision)
    "waf_bypass_timeout": (
        30,
        "WAF bypass engine HTTP timeout in seconds.",
    ),
    "fuzzer_threads": (
        5,
        "Default concurrent threads for quick_fuzz.",
    ),
    "fuzzer_timeout": (
        15,
        "Default per-request timeout for fuzzer in seconds.",
    ),
    "fuzzer_quick_max_payloads_per_type": (
        10,
        "Max payloads per vuln type for quick_fuzz. Lower = faster, higher = more thorough.",
    ),
    "fuzzer_quick_timeout_seconds": (
        300.0,
        "Aggregate timeout for quick_fuzz in seconds. Prevents stuck state.",
    ),
    "fuzzer_deep_timeout_seconds": (
        300.0,
        "Aggregate timeout for deep_fuzz in seconds.",
    ),
    "fuzzer_advanced_max_payloads": (
        20,
        "Max payloads for advanced_fuzz.",
    ),
    "fuzzer_waf_bypass_limit": (
        5,
        "Max WAF bypass attempts per param:vuln_type combination before giving up.",
    ),
    "rate_limiter_base_delay": (
        1.0,
        "Base delay between requests in seconds. Per-domain delay is overridden to 1.0/threads by Fuzzer.",
    ),
    "rate_limiter_max_delay": (
        60.0,
        "Maximum delay between requests in seconds after repeated rate limits.",
    ),
    "rate_limiter_max_retries": (
        5,
        "Max retries on rate limit (429) or timeout before giving up.",
    ),
    "rate_limiter_http_timeout": (
        30,
        "HTTP request timeout in seconds for rate limiter client.",
    ),
    "rate_limiter_abort_threshold": (
        10,
        "Consecutive 429 responses before aborting all requests to a domain.",
    ),
    "observe_request_timeout": (
        15,
        "HTTP request timeout for observe/intercept tools in seconds.",
    ),
    "ollama_status_timeout": (
        3.5,
        "Timeout for Ollama health check in seconds.",
    ),
    "ollama_status_sticky_ok_seconds": (
        120.0,
        "How long to consider Ollama 'healthy' after a successful check.",
    ),
    "mcp_probe_timeout": (
        45.0,
        "Timeout for MCP server probe in seconds.",
    ),
    "mcp_tools_list_timeout": (
        30.0,
        "Timeout for MCP tools list request in seconds.",
    ),
    "caido_token_timeout": (
        1.5,
        "Timeout for Caido auth token fetch in seconds.",
    ),
    "agent_idle_hard_timeout": (
        1800.0,
        "Hard timeout for agent idle state in seconds. Env var AIRECON_AGENT_IDLE_HARD_TIMEOUT overrides.",
    ),
    "exploration_meaningful_evidence_threshold": (
        0.65,
        "Minimum confidence score for evidence to be considered 'meaningful' in exploration mode.",
    ),
    "agent_max_browser_visits_per_domain": (
        3,
        "Max browser tool visits per domain before blocking.",
    ),
    "agent_command_hash_cache_limit": (
        5000,
        "Max entries in command deduplication hash cache.",
    ),
    "agent_command_hash_cache_prune_target": (
        2500,
        "Prune command hash cache to this size when limit is exceeded.",
    ),
    "agent_max_empty_retries": (
        4,
        "Max retries for empty LLM responses before giving up.",
    ),
    "agent_ctf_max_iterations": (
        150,
        "Max agent iterations in CTF mode.",
    ),
    "pipeline_recon_max_iterations": (
        500,
        "Max iterations for RECON phase.",
    ),
    "pipeline_analysis_max_iterations": (
        300,
        "Max iterations for ANALYSIS phase.",
    ),
    "pipeline_exploit_max_iterations": (
        800,
        "Max iterations for EXPLOIT phase.",
    ),
    "pipeline_report_max_iterations": (
        100,
        "Max iterations for REPORT phase.",
    ),
    "pipeline_recon_budget": (
        10,
        "Tool budget for RECON phase.",
    ),
    "pipeline_analysis_budget": (
        30,
        "Tool budget for ANALYSIS phase.",
    ),
    "pipeline_exploit_budget": (
        60,
        "Tool budget for EXPLOIT phase.",
    ),
    "pipeline_report_budget": (
        0,
        "Tool budget for REPORT phase (0 = blocked).",
    ),
    # Phase dynamic settings (previously hardcoded in Python files)
    "pipeline_output_parser_max_items_recon": (
        200,
        "Max items for RECON phase in output parser.",
    ),
    "pipeline_output_parser_max_items_analysis": (
        150,
        "Max items for ANALYSIS phase in output parser.",
    ),
    "pipeline_output_parser_max_items_exploit": (
        50,
        "Max items for EXPLOIT phase in output parser.",
    ),
    "pipeline_output_parser_max_items_report": (
        25,
        "Max items for REPORT phase in output parser.",
    ),
    "pipeline_max_iterations_cap": (
        350,
        "Hard cap for max iterations per phase to prevent infinite loops.",
    ),
    "pipeline_counterfactual_interval_simple": (
        8,
        "Counterfactual injection interval for simple targets (few vulns).",
    ),
    "pipeline_counterfactual_interval_complex": (
        5,
        "Counterfactual injection interval for complex targets (many vulns).",
    ),
    "pipeline_stagnation_vuln_baseline_iterations": (
        30,
        "Iterations before triggering stagnation escape in EXPLOIT phase.",
    ),
    "pipeline_analysis_min_injection_points": (
        3,
        "Minimum injection points to find before ANALYSIS phase can transition.",
    ),
    "pipeline_recon_artifacts_scan_threshold": (
        3,
        "Minimum scan count before recon artifacts criterion can be met.",
    ),
    "pipeline_min_iterations_per_phase": (
        10,
        "Minimum iterations before phase can transition.",
    ),
    "pipeline_advanced_hints_failure_threshold": (
        3,
        "Consecutive failures before adding advanced hints.",
    ),
    "pipeline_recon_strong_signals_threshold": (
        2,
        "Minimum strong signals needed for RECON transition.",
    ),
    "pipeline_counterfactual_vuln_threshold": (
        5,
        "Vuln count threshold for switching counterfactual interval.",
    ),
    "pipeline_exploit_min_signals": (
        2,
        "Minimum signals needed in EXPLOIT phase before transition.",
    ),
    "agent_graph_max_iterations_recon": (
        150,
        "Max iterations for recon node in agent graph.",
    ),
    "agent_graph_max_iterations_analyzer": (
        100,
        "Max iterations for analyzer node in agent graph.",
    ),
    "agent_graph_max_iterations_exploiter": (
        200,
        "Max iterations for exploiter node in agent graph.",
    ),
    "agent_graph_max_iterations_reporter": (
        100,
        "Max iterations for reporter node in agent graph.",
    ),
    # Phase tool budgets (previously in tools_meta.json)
    "pipeline_tool_budget_recon_quick_fuzz": (
        10,
        "Tool budget: quick_fuzz for RECON phase.",
    ),
    "pipeline_tool_budget_recon_advanced_fuzz": (
        5,
        "Tool budget: advanced_fuzz for RECON phase.",
    ),
    "pipeline_tool_budget_recon_deep_fuzz": (
        0,
        "Tool budget: deep_fuzz for RECON phase.",
    ),
    "pipeline_tool_budget_recon_caido_automate": (
        5,
        "Tool budget: caido_automate for RECON phase.",
    ),
    "pipeline_tool_budget_recon_create_vulnerability_report": (
        2,
        "Tool budget: create_vulnerability_report for RECON phase.",
    ),
    "pipeline_tool_budget_analysis_advanced_fuzz": (
        20,
        "Tool budget: advanced_fuzz for ANALYSIS phase.",
    ),
    "pipeline_tool_budget_analysis_deep_fuzz": (
        5,
        "Tool budget: deep_fuzz for ANALYSIS phase.",
    ),
    "pipeline_tool_budget_analysis_create_vulnerability_report": (
        5,
        "Tool budget: create_vulnerability_report for ANALYSIS phase.",
    ),
    "pipeline_tool_budget_exploit_advanced_fuzz": (
        50,
        "Tool budget: advanced_fuzz for EXPLOIT phase.",
    ),
    "pipeline_tool_budget_exploit_deep_fuzz": (
        25,
        "Tool budget: deep_fuzz for EXPLOIT phase.",
    ),
    "pipeline_tool_budget_exploit_quick_fuzz": (
        30,
        "Tool budget: quick_fuzz for EXPLOIT phase.",
    ),
    "pipeline_tool_budget_exploit_caido_automate": (
        40,
        "Tool budget: caido_automate for EXPLOIT phase.",
    ),
    "pipeline_tool_budget_report_execute": (
        50,
        "Tool budget: execute for REPORT phase.",
    ),
    "pipeline_tool_budget_report_advanced_fuzz": (
        2,
        "Tool budget: advanced_fuzz for REPORT phase.",
    ),
    "pipeline_tool_budget_report_deep_fuzz": (
        1,
        "Tool budget: deep_fuzz for REPORT phase.",
    ),
    "pipeline_tool_budget_report_quick_fuzz": (
        2,
        "Tool budget: quick_fuzz for REPORT phase.",
    ),
    # Phase confidence thresholds (previously in tools_meta.json)
    "pipeline_confidence_threshold_recon": (
        0.6,
        "Confidence threshold for RECON phase transition.",
    ),
    "pipeline_confidence_threshold_analysis": (
        0.58,
        "Confidence threshold for ANALYSIS phase transition.",
    ),
    "pipeline_confidence_threshold_exploit": (
        0.55,
        "Confidence threshold for EXPLOIT phase transition.",
    ),
    "pipeline_confidence_threshold_report": (
        0.5,
        "Confidence threshold for REPORT phase transition.",
    ),
    "model_max_tool_iterations": (
        50,
        "MAX_TOOL_ITERATIONS constant for agent state model.",
    ),
    "model_max_tool_history": (
        100,
        "MAX_TOOL_HISTORY constant for agent state model.",
    ),
    "model_max_objectives": (
        64,
        "MAX_OBJECTIVES constant for agent state model.",
    ),
    "model_max_evidence": (
        200,
        "MAX_EVIDENCE constant for agent state model.",
    ),
    "model_max_causal_observations": (
        2000,
        "MAX_CAUSAL_OBSERVATIONS constant for agent state model.",
    ),
    "model_max_tool_result_chars": (
        50000,
        "MAX_TOOL_RESULT_CHARS (in thousands) for agent state model.",
    ),
    "model_min_confidence_for_preservation": (
        0.75,
        "MIN_CONFIDENCE_FOR_PRESERVATION threshold for agent state model.",
    ),
    # Causal observation confidence (moved from tools_meta.json)
    "causal_confidence_technology_detected": (
        0.86,
        "Confidence for technology_detected causal observation.",
    ),
    "causal_confidence_endpoint_observed": (
        0.82,
        "Confidence for endpoint_observed causal observation.",
    ),
    "causal_confidence_endpoint_accessible": (
        0.80,
        "Confidence for endpoint_accessible causal observation.",
    ),
    "causal_confidence_service_exposed": (
        0.80,
        "Confidence for service_exposed causal observation.",
    ),
    "causal_confidence_port_state_observed": (
        0.78,
        "Confidence for port_state_observed causal observation.",
    ),
    "causal_confidence_endpoint_discovered": (
        0.74,
        "Confidence for endpoint_discovered causal observation.",
    ),
    "causal_confidence_asset_discovered": (
        0.72,
        "Confidence for asset_discovered causal observation.",
    ),
    "causal_confidence_vulnerability_signal": (
        0.68,
        "Confidence for vulnerability_signal causal observation.",
    ),
    "causal_confidence_tool_output_observed": (
        0.55,
        "Confidence for tool_output_observed causal observation.",
    ),
    "verification_enabled": (
        True,
        "Enable zero-FP verification engine. When True, all findings go through multi-stage verification.",
    ),
    "verification_enable_replay": (
        True,
        "Enable replay verification. Re-tests findings with independent payloads.",
    ),
    "verification_enable_cross_tool": (
        True,
        "Enable cross-tool validation. Requires 2+ independent signals.",
    ),
    "verification_enable_negative_test": (
        True,
        "Enable negative testing. Tests clean payloads to calibrate FP rate.",
    ),
    "verification_enable_fp_detection": (
        True,
        "Enable false positive detection. Detects dynamic content, WAF, CDN, honeypots.",
    ),
    "verification_max_replays": (
        3,
        "Max replay payloads per finding. Higher = more thorough but slower.",
    ),
    "verification_timeout": (
        15,
        "HTTP timeout per verification request in seconds.",
    ),
    "verification_min_certified_confidence": (
        0.90,
        "Minimum confidence for CERTIFIED tier. Findings below this are VALIDATED or CONFIRMED.",
    ),
    "verification_min_report_confidence": (
        0.75,
        "Minimum confidence required before a finding can be included in a vulnerability report.",
    ),
    "intelligence_enabled": (
        True,
        "Enable genius-level intelligence features (adaptive learning, generative fuzzing, target profiling).",
    ),
    "intelligence_adaptive_learning_enabled": (
        True,
        "Enable adaptive learning engine for tool performance tracking and strategy reinforcement.",
    ),
    "intelligence_adaptive_min_observations": (
        3,
        "Minimum tool observations before making recommendations.",
    ),
    "intelligence_generative_fuzzing_enabled": (
        True,
        "Enable generative fuzzing engine with genetic algorithm payload evolution.",
    ),
    "intelligence_generative_population_size": (
        50,
        "Population size for generative fuzzing genetic algorithm.",
    ),
    "intelligence_generative_max_generations": (
        10,
        "Max generations for generative fuzzing evolution.",
    ),
    "intelligence_target_profiling_enabled": (
        True,
        "Enable intelligent target profiling (tech detection, security posture, attack surface mapping).",
    ),
    "intelligence_attack_chain_synthesis_enabled": (
        True,
        "Enable automatic attack chain synthesis with kill-chain mapping.",
    ),
    "payload_memory_enabled": (
        True,
        "Enable payload memory engine. Tracks payload success/failure per target to avoid repeating failed payloads.",
    ),
    "payload_memory_max_records": (
        10000,
        "Maximum payload records to keep in memory before pruning.",
    ),
    "payload_memory_ttl_days": (
        7,
        "Days to keep payload records before they expire.",
    ),
    "per_tool_timeout_seconds": (
        600.0,
        "Maximum time allowed for a single tool execution (seconds). Prevents hung tools from blocking the agent loop.",
    ),
    "response_timing_alert_threshold_ms": (
        30000,
        "Average tool response time threshold (milliseconds) that triggers a warning injection into agent context.",
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
    (
        "External Services",
        [
            "caido_graphql_url",
            "searxng_url",
            "searxng_engines",
        ],
    ),
    (
        "Browser Automation",
        [
            "browser_cdp_port",
            "browser_cdp_bind_address",
            "browser_connect_timeout_ms",
            "browser_navigation_timeout_ms",
            "browser_login_form_wait_ms",
            "browser_page_load_timeout_ms",
            "browser_oauth_callback_timeout_ms",
            "browser_totp_fill_timeout_ms",
            "browser_screenshot_timeout_ms",
            "browser_page_load_delay",
            "browser_action_timeout",
        ],
    ),
    (
        "Fuzzer",
        [
            "fuzzer_threads",
            "fuzzer_timeout",
            "fuzzer_quick_max_payloads_per_type",
            "fuzzer_quick_timeout_seconds",
            "fuzzer_deep_timeout_seconds",
            "fuzzer_advanced_max_payloads",
            "fuzzer_waf_bypass_limit",
        ],
    ),
    (
        "Rate Limiter",
        [
            "rate_limiter_base_delay",
            "rate_limiter_max_delay",
            "rate_limiter_max_retries",
            "rate_limiter_http_timeout",
            "rate_limiter_abort_threshold",
        ],
    ),
    (
        "WAF & Security",
        [
            "waf_bypass_timeout",
        ],
    ),
    (
        "Observation Tools",
        [
            "observe_request_timeout",
        ],
    ),
    (
        "MCP Integration",
        [
            "mcp_probe_timeout",
            "mcp_tools_list_timeout",
        ],
    ),
    (
        "Caido Proxy",
        [
            "caido_token_timeout",
            "agent_idle_hard_timeout",
        ],
    ),
    (
        "Health Checks",
        [
            "ollama_status_timeout",
            "ollama_status_sticky_ok_seconds",
        ],
    ),
    (
        "Exploration & Intelligence",
        [
            "exploration_meaningful_evidence_threshold",
        ],
    ),
    (
        "Agent Limits",
        [
            "agent_max_browser_visits_per_domain",
            "agent_command_hash_cache_limit",
            "agent_command_hash_cache_prune_target",
            "agent_max_empty_retries",
            "agent_ctf_max_iterations",
        ],
    ),
    (
        "Phase Budgets",
        [
            "pipeline_recon_max_iterations",
            "pipeline_analysis_max_iterations",
            "pipeline_exploit_max_iterations",
            "pipeline_report_max_iterations",
            "pipeline_recon_budget",
            "pipeline_analysis_budget",
            "pipeline_exploit_budget",
            "pipeline_report_budget",
        ],
    ),
    (
        "Model Constants",
        [
            "model_max_tool_iterations",
            "model_max_tool_history",
            "model_max_objectives",
            "model_max_evidence",
            "model_max_causal_observations",
            "model_max_tool_result_chars",
            "model_min_confidence_for_preservation",
        ],
    ),
    (
        "Verification Engine (Zero False Positive)",
        [
            "verification_enabled",
            "verification_enable_replay",
            "verification_enable_cross_tool",
            "verification_enable_negative_test",
            "verification_enable_fp_detection",
            "verification_max_replays",
            "verification_timeout",
            "verification_min_certified_confidence",
            "verification_min_report_confidence",
        ],
    ),
    (
        "Intelligence Engine (Genius-Level)",
        [
            "intelligence_enabled",
            "intelligence_adaptive_learning_enabled",
            "intelligence_adaptive_min_observations",
            "intelligence_generative_fuzzing_enabled",
            "intelligence_generative_population_size",
            "intelligence_generative_max_generations",
            "intelligence_target_profiling_enabled",
            "intelligence_attack_chain_synthesis_enabled",
        ],
    ),
    (
        "Payload Memory Engine",
        [
            "payload_memory_enabled",
            "payload_memory_max_records",
            "payload_memory_ttl_days",
        ],
    ),
    (
        "Resilience & Performance",
        [
            "per_tool_timeout_seconds",
            "response_timing_alert_threshold_ms",
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
                candidates: list[Path] = []
                env_override = os.getenv("AIRECON_WORKSPACE")
                if env_override:
                    candidates.append(Path(env_override))
                candidates.extend(
                    [
                        Path.cwd() / "workspace",
                        Path.home() / APP_DIR_NAME / "workspace",
                        Path(tempfile.gettempdir()) / "airecon-workspace",
                    ]
                )
                for candidate in candidates:
                    try:
                        candidate.mkdir(parents=True, exist_ok=True)
                        _workspace_root_cache = candidate
                        break
                    except PermissionError as e:
                        logger.warning(
                            "Workspace path not writable (%s): %s", candidate, e
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed creating workspace path (%s): %s", candidate, e
                        )
                if _workspace_root_cache is None:
                    raise RuntimeError(
                        "Unable to create workspace directory. "
                        "Set AIRECON_WORKSPACE to a writable path."
                    )
    return _workspace_root_cache


# ── Essential keys that get written to config.yaml ──────────────────────────
# Only these are written to config.yaml. All other values stay as defaults
# in config.py to keep the config file clean and minimal.
_ESSENTIAL_CONFIG_KEYS: set[str] = {
    "proxy_host",
    "proxy_port",
    "ollama_url",
    "ollama_model",
    "ollama_timeout",
    "ollama_num_ctx",
    "ollama_num_ctx_small",
    "ollama_num_predict",
    "ollama_num_keep",
    "ollama_temperature",
    "ollama_enable_thinking",
    "ollama_thinking_mode",
    "command_timeout",
    "docker_memory_limit",
    "deep_recon_autostart",
    "agent_recon_mode",
    "allow_destructive_testing",
}


def _write_yaml_with_comments(config: dict, filepath: Path) -> None:
    from airecon._version import __version__

    filepath.parent.mkdir(parents=True, exist_ok=True)
    lines = []

    lines.append("#╔══════════════════════════════════════════════════════════╗")
    lines.append("#║              AIRecon Configuration File                  ║")
    lines.append("#║                                                          ║")
    lines.append(f"#║  Version: {__version__:<46} ║")
    lines.append("#║  Format: YAML (supports comments)                        ║")
    lines.append("#║  Edit this file to customize AIRecon behavior            ║")
    lines.append("#║                                                          ║")
    lines.append("#║  Docs: https://github.com/pikpikcu/airecon               ║")
    lines.append("#║                                                          ║")
    lines.append("#║  NOTE: Only essential settings are written here.         ║")
    lines.append("#║  All other values use sensible defaults in config.py.    ║")
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

    # Only write essential keys
    essential_keys = _ESSENTIAL_CONFIG_KEYS
    written_keys: set[str] = set()

    for category, keys in _CONFIG_CATEGORIES:
        category_keys = [
            k for k in keys if k in essential_keys and k not in written_keys
        ]
        if not category_keys:
            continue

        lines.append("")
        lines.append(f"# {'=' * 38}")
        lines.append(f"# {category}")
        lines.append(f"# {'=' * 38}")

        for key in category_keys:
            if key in config:
                value = config[key]
                comment = _CONFIG_SCHEMA.get(key, ("", ""))[1]

                # Skip caido URL — always use default
                if key == "caido_graphql_url":
                    continue

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
                written_keys.add(key)

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
    pipeline_recon_artifacts_scan_threshold: int
    pipeline_recon_strong_signals_threshold: int
    pipeline_analysis_min_injection_points: int
    pipeline_exploit_min_signals: int
    pipeline_counterfactual_interval_simple: int
    pipeline_counterfactual_interval_complex: int
    pipeline_counterfactual_vuln_threshold: int
    pipeline_stagnation_vuln_baseline_iterations: int
    pipeline_min_iterations_per_phase: int
    pipeline_advanced_hints_failure_threshold: int
    pipeline_max_iterations_cap: int
    pipeline_output_parser_max_items_recon: int
    pipeline_output_parser_max_items_analysis: int
    pipeline_output_parser_max_items_exploit: int
    pipeline_output_parser_max_items_report: int

    agent_max_conversation_messages: int
    agent_compression_trigger_ratio: float
    agent_uncompressed_keep_count: int
    agent_llm_compression_num_ctx: int
    agent_llm_compression_num_predict: int
    agent_context_reset_cooldown_seconds: int

    caido_graphql_url: str
    browser_cdp_port: int
    browser_cdp_bind_address: str
    browser_connect_timeout_ms: int
    browser_navigation_timeout_ms: int
    browser_login_form_wait_ms: int
    browser_page_load_timeout_ms: int
    browser_oauth_callback_timeout_ms: int
    browser_totp_fill_timeout_ms: int
    browser_screenshot_timeout_ms: int
    # CAPTCHA uses ollama_model for vision (qwen3.5 supports images)
    waf_bypass_timeout: int
    fuzzer_threads: int
    fuzzer_timeout: int
    fuzzer_quick_max_payloads_per_type: int
    fuzzer_quick_timeout_seconds: float
    fuzzer_deep_timeout_seconds: float
    fuzzer_advanced_max_payloads: int
    fuzzer_waf_bypass_limit: int
    rate_limiter_base_delay: float
    rate_limiter_max_delay: float
    rate_limiter_max_retries: int
    rate_limiter_http_timeout: int
    rate_limiter_abort_threshold: int
    observe_request_timeout: int
    ollama_status_timeout: float
    ollama_status_sticky_ok_seconds: float
    mcp_probe_timeout: float
    mcp_tools_list_timeout: float
    caido_token_timeout: float
    agent_idle_hard_timeout: float
    exploration_meaningful_evidence_threshold: float
    agent_max_browser_visits_per_domain: int
    agent_command_hash_cache_limit: int
    agent_command_hash_cache_prune_target: int
    agent_max_empty_retries: int
    agent_ctf_max_iterations: int
    pipeline_recon_max_iterations: int
    pipeline_analysis_max_iterations: int
    pipeline_exploit_max_iterations: int
    pipeline_report_max_iterations: int
    pipeline_recon_budget: int
    pipeline_analysis_budget: int
    pipeline_exploit_budget: int
    pipeline_report_budget: int
    pipeline_tool_budget_recon_quick_fuzz: int
    pipeline_tool_budget_recon_advanced_fuzz: int
    pipeline_tool_budget_recon_deep_fuzz: int
    pipeline_tool_budget_recon_caido_automate: int
    pipeline_tool_budget_recon_create_vulnerability_report: int
    pipeline_tool_budget_analysis_advanced_fuzz: int
    pipeline_tool_budget_analysis_deep_fuzz: int
    pipeline_tool_budget_analysis_create_vulnerability_report: int
    pipeline_tool_budget_exploit_advanced_fuzz: int
    pipeline_tool_budget_exploit_deep_fuzz: int
    pipeline_tool_budget_exploit_quick_fuzz: int
    pipeline_tool_budget_exploit_caido_automate: int
    pipeline_tool_budget_report_execute: int
    pipeline_tool_budget_report_advanced_fuzz: int
    pipeline_tool_budget_report_deep_fuzz: int
    pipeline_tool_budget_report_quick_fuzz: int
    pipeline_confidence_threshold_recon: float
    pipeline_confidence_threshold_analysis: float
    pipeline_confidence_threshold_exploit: float
    pipeline_confidence_threshold_report: float
    agent_graph_max_iterations_recon: int
    agent_graph_max_iterations_analyzer: int
    agent_graph_max_iterations_exploiter: int
    agent_graph_max_iterations_reporter: int
    model_max_tool_iterations: int
    model_max_tool_history: int
    model_max_objectives: int
    model_max_evidence: int
    model_max_causal_observations: int
    model_max_tool_result_chars: int
    model_min_confidence_for_preservation: float
    causal_confidence_technology_detected: float
    causal_confidence_endpoint_observed: float
    causal_confidence_endpoint_accessible: float
    causal_confidence_service_exposed: float
    causal_confidence_port_state_observed: float
    causal_confidence_endpoint_discovered: float
    causal_confidence_asset_discovered: float
    causal_confidence_vulnerability_signal: float
    causal_confidence_tool_output_observed: float

    verification_enabled: bool
    verification_enable_replay: bool
    verification_enable_cross_tool: bool
    verification_enable_negative_test: bool
    verification_enable_fp_detection: bool
    verification_max_replays: int
    verification_timeout: int
    verification_min_certified_confidence: float
    verification_min_report_confidence: float

    intelligence_enabled: bool
    intelligence_adaptive_learning_enabled: bool
    intelligence_adaptive_min_observations: int
    intelligence_generative_fuzzing_enabled: bool
    intelligence_generative_population_size: int
    intelligence_generative_max_generations: int
    intelligence_target_profiling_enabled: bool
    intelligence_attack_chain_synthesis_enabled: bool

    payload_memory_enabled: bool
    payload_memory_max_records: int
    payload_memory_ttl_days: int

    per_tool_timeout_seconds: float
    response_timing_alert_threshold_ms: float

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        if config_path:
            config_file = Path(config_path).expanduser()
            config_dir = config_file.parent
            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)
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
            # LLM config
            "ollama_temperature": (0.0, 1.2),
            "ollama_num_predict": (64, 65536),
            "ollama_num_ctx": (-1, 262144),
            "ollama_num_ctx_small": (2048, 131072),
            "ollama_repeat_penalty": (1.0, 1.5),
            "ollama_num_keep": (0, 32768),
            "ollama_max_concurrent_requests": (1, 8),
            # Timeouts
            "ollama_timeout": (10.0, 1800.0),
            "ollama_chunk_timeout": (30.0, 1200.0),
            "command_timeout": (30.0, 7200.0),
            "per_tool_timeout_seconds": (10.0, 3600.0),
            "response_timing_alert_threshold_ms": (1000, 300000),
            # Ratios & intensities
            "agent_exploration_intensity": (0.1, 1.0),
            "agent_exploration_temperature": (0.0, 1.0),
            "agent_phase_creative_temperature": (0.0, 1.0),
            "agent_compression_trigger_ratio": (0.3, 0.95),
            "vuln_similarity_threshold": (0.3, 0.95),
            "evidence_similarity_threshold": (0.3, 0.95),
            "verification_min_certified_confidence": (0.5, 1.0),
            "verification_min_report_confidence": (0.3, 0.95),
            # Ports
            "proxy_port": (1, 65535),
            "browser_cdp_port": (1, 65535),
            # Iterations & limits
            "agent_max_tool_iterations": (50, 5000),
            "agent_ctf_max_iterations": (20, 1000),
            "agent_repeat_tool_call_limit": (1, 10),
            "agent_missing_tool_retry_limit": (1, 10),
            "agent_plan_revision_interval": (5, 200),
            "agent_stagnation_threshold": (1, 50),
            "agent_tool_diversity_window": (2, 30),
            "agent_max_same_tool_streak": (1, 10),
            "agent_max_conversation_messages": (100, 5000),
            "agent_uncompressed_keep_count": (3, 100),
            "agent_max_browser_visits_per_domain": (1, 20),
            "agent_command_hash_cache_limit": (500, 50000),
            "agent_max_empty_retries": (1, 10),
            # Browser timeouts (ms)
            "browser_connect_timeout_ms": (500, 30000),
            "browser_navigation_timeout_ms": (5000, 300000),
            "browser_login_form_wait_ms": (1000, 60000),
            "browser_page_load_timeout_ms": (2000, 120000),
            "browser_oauth_callback_timeout_ms": (5000, 120000),
            "browser_totp_fill_timeout_ms": (1000, 30000),
            "browser_screenshot_timeout_ms": (1000, 30000),
            # CAPTCHA — no numeric validation needed for model name
            # Pipeline
            "pipeline_recon_max_iterations": (50, 2000),
            "pipeline_analysis_max_iterations": (50, 2000),
            "pipeline_exploit_max_iterations": (50, 3000),
            "pipeline_report_max_iterations": (10, 500),
            "pipeline_recon_min_subdomains": (0, 50),
            "pipeline_recon_min_urls": (0, 20),
            "pipeline_recon_soft_timeout": (10, 500),
            "pipeline_recon_budget": (0, 200),
            "pipeline_analysis_budget": (0, 200),
            "pipeline_exploit_budget": (0, 500),
            "pipeline_report_budget": (0, 200),
            # Model constants
            "model_max_tool_iterations": (10, 500),
            "model_max_tool_history": (10, 500),
            "model_max_objectives": (10, 200),
            "model_max_evidence": (20, 1000),
            "model_max_causal_observations": (100, 10000),
            "model_tool_result_chars": (5000, 200000),
            "model_min_confidence_for_preservation": (0.1, 0.99),
            # Fuzzer
            "fuzzer_threads": (1, 50),
            "fuzzer_timeout": (1, 120),
            "fuzzer_quick_max_payloads_per_type": (1, 100),
            "fuzzer_quick_timeout_seconds": (30.0, 1800.0),
            "fuzzer_deep_timeout_seconds": (30.0, 1800.0),
            "fuzzer_advanced_max_payloads": (1, 200),
            "fuzzer_waf_bypass_limit": (1, 50),
            # Rate limiter
            "rate_limiter_base_delay": (0.0, 60.0),
            "rate_limiter_max_delay": (1.0, 600.0),
            "rate_limiter_max_retries": (1, 30),
            "rate_limiter_http_timeout": (5, 120),
            "rate_limiter_abort_threshold": (3, 50),
            # Verification
            "verification_max_replays": (1, 20),
            "verification_timeout": (5, 120),
            # Intelligence
            "intelligence_adaptive_min_observations": (1, 20),
            "intelligence_generative_population_size": (10, 500),
            "intelligence_generative_max_generations": (1, 100),
            # Payload memory
            "payload_memory_max_records": (100, 100000),
            "payload_memory_ttl_days": (1, 365),
            # Misc
            "waf_bypass_timeout": (5, 300),
            "observe_request_timeout": (5, 120),
            "ollama_status_timeout": (1.0, 30.0),
            "ollama_status_sticky_ok_seconds": (10.0, 600.0),
            "mcp_probe_timeout": (5.0, 300.0),
            "mcp_tools_list_timeout": (5.0, 300.0),
            "caido_token_timeout": (0.5, 30.0),
            "agent_idle_hard_timeout": (60.0, 7200.0),
            "agent_context_reset_cooldown_seconds": (10.0, 3600.0),
            "browser_page_load_delay": (0.1, 10.0),
            "browser_action_timeout": (10, 180),
            "ollama_keep_alive": (-1, 86400),
            "agent_llm_compression_num_ctx": (1024, 65536),
            "agent_llm_compression_num_predict": (64, 4096),
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

        # Validate required fields
        if not merged.get("ollama_url"):
            logger.error(
                "ollama_url is REQUIRED. Set it in ~/.airecon/config.yaml "
                "or via AIRECON_OLLAMA_URL environment variable. "
                "Example: http://127.0.0.1:11434 or http://your-server:11434"
            )

        return cls(**merged)


_config: Config | None = None
_config_mtime: float = 0.0
_config_path: Path | None = None
_config_init_lock = threading.Lock()


def _get_config_path(config_path: str | Path | None = None) -> Path:
    if config_path:
        return Path(config_path).expanduser()
    return Path.home() / APP_DIR_NAME / CONFIG_FILENAME


def get_config(config_path: str | None = None) -> Config:
    global _config, _config_mtime, _config_path

    if _config_path is None:
        _config_path = _get_config_path(config_path)

    if _config is not None:
        try:
            try:
                asyncio.get_running_loop()

                global _config_reload_lock
                if _config_reload_lock is None:
                    _config_reload_lock = asyncio.Lock()

            except RuntimeError:
                pass

            with _config_init_lock:
                current_mtime = (
                    _config_path.stat().st_mtime if _config_path.exists() else 0.0
                )
                if current_mtime > _config_mtime:
                    logger.info("Config file changed — reloading from %s", _config_path)
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
            except Exception as e:
                logger.debug("Config reload check failed: %s", e)

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
