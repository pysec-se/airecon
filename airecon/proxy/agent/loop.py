from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shlex
import warnings
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from ..config import get_config, get_workspace_root
from ..docker import DockerEngine
from ..ollama import OllamaClient
from ..system import (
    _is_ctf_target,
    auto_load_skills_for_message,
    auto_load_skills_for_technologies,
    get_system_prompt,
)
from .executors import _ExecutorMixin
from .file_reference import (
    build_injection_message,
    parse_refs,
    resolve_ref,
    strip_refs,
    workspace_name_for_ref,
)
from .formatters import _FormatterMixin
from .models import MAX_TOOL_ITERATIONS, AgentEvent, AgentState
from .output_parser import parse_tool_output
from .pipeline import PipelineEngine, PipelinePhase
from .session import (
    SessionData,
    find_prior_session,
    load_session,
    merge_prior_findings,
    record_tested_endpoint,
    save_session,
    session_to_context,
    update_from_parsed_output,
)
from .tool_defs import get_tool_definitions
from dataclasses import asdict as _asdict
from .chain_planner import ChainStep as _ChainStep
from .chain_planner import ExploitChain as _ExploitChain
from .chain_planner import build_chain_context, plan_chains
from .validators import _ValidatorMixin
from .waf_detector import (
    build_waf_bypass_context,
    detect_waf_from_response,
    merge_waf_profiles,
    rank_bypass_strategies,
)
from .workspace import _WorkspaceMixin
from .loop_inference import _InferenceMixin
from .loop_exploration import _ExplorationMixin, _MEANINGFUL_EVIDENCE_THRESHOLD
from .loop_objectives import _ObjectivesMixin
from .loop_supervision import _SupervisionMixin
from .loop_context import _ContextMixin

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable ({_e}); tool catalog features disabled.")
    _TOOLS_META = {}


logger = logging.getLogger("airecon.agent")

# Maximum retries for empty Ollama responses before surfacing error.
# Each retry waits 5s × attempt (5s, 10s, 15s, 20s).
_MAX_EMPTY_RETRIES = 4


class AgentLoop(
    _ValidatorMixin,
    _FormatterMixin,
    _WorkspaceMixin,
    _ExecutorMixin,
    _InferenceMixin,
    _ExplorationMixin,
    _ObjectivesMixin,
    _SupervisionMixin,
    _ContextMixin,
):
    # Extracts embedded <tool_call>…</tool_call> blocks from model text output
    _TOOL_CALL_RE = re.compile(
        r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
        re.DOTALL | re.IGNORECASE,
    )
    # Detects bash/shell code blocks the LLM writes as plain text instead of
    # calling a tool.  Pattern:  ```bash\n...\n```  or  ```sh\n...\n```
    # A block with ≥1 non-empty line = hallucinated command execution.
    _FAKE_CMD_BLOCK_RE = re.compile(
        r"```(?:bash|sh|shell|cmd|terminal|zsh)?\s*\n(.+?)```",
        re.DOTALL | re.IGNORECASE,
    )
    # Detects plain-text shell commands written outside any code block.
    # Two patterns are considered unambiguous:
    #   1. cd /workspace/<target> && ...  — AIRecon workspace invocation pattern
    #   2. curl/wget followed by an http(s) URL AND a shell operator (&&, |, ;, \)
    #      The shell-operator requirement avoids false positives on explanation text
    #      like "you can use curl https://target.com to verify" which legitimately
    #      starts a line but is not a hallucinated command invocation.
    # Both patterns indicate the LLM is "writing" commands rather than calling
    # the execute tool.
    _FAKE_PLAIN_CMD_RE = re.compile(
        r"(?m)^[ \t]*"
        r"(?:"
        r"cd\s+/workspace/\S+\s*&&"                    # cd /workspace/target &&
        r"|(?:curl|wget)\s+https?://\S+\s*(?:&&|\||;|\\)" # curl/wget https://... followed by shell operator (&& | ; or line-continuation \)
        r")",
    )

    # Tools exempt from dedup (interactive / stateful operations that must be
    # re-runnable)
    _DEDUP_EXEMPT_TOOLS = frozenset({
        "create_file",
        "create_vulnerability_report",
        "spawn_agent",
    })
    # browser_action actions that are always interactive and must not be
    # deduped
    _DEDUP_EXEMPT_BROWSER_ACTIONS = frozenset({
        "click", "type", "press_key", "scroll_down", "scroll_up",
        "wait", "get_console_logs", "get_network_logs",
        # Auth actions must never be deduped — re-login / MFA retry requires re-execution
        "login_form", "handle_totp", "save_auth_state", "inject_cookies", "oauth_authorize",
    })
    # Max number of times the same CTF-local challenge can be seen before CTF
    # mode kicks in
    _CTF_MAX_ITERATIONS = 150
    def __init__(self, ollama: OllamaClient, engine: DockerEngine) -> None:
        self.ollama = ollama
        self.engine = engine
        self.state = AgentState()
        self._tools_ollama: list[dict[str, Any]] | None = None
        self._last_output_file: str | None = None
        self._executed_tool_counts: dict[tuple[str, str], int] = {}
        # Hash-based dedup: stores MD5(tool_name+args) to block re-execution of
        # identical commands
        self._executed_cmd_hashes: set[str] = set()
        self._initial_messages: list[dict[str, Any]] = []
        self._stop_requested: bool = False
        self._consecutive_failures: int = 0
        # Tracks consecutive iterations where LLM returned no tool calls.
        # Used to escalate nudges when the model is stuck in text-only mode.
        self._no_tool_iterations: int = 0
        self._stagnation_iterations: int = 0
        self._recent_tool_names: list[str] = []
        self._last_evidence_count: int = 0
        self._watchdog_forced_calls: int = 0
        self._empty_response_retry_count: int = 0
        # Tracks the phase at the previous iteration to detect phase transitions
        # and reset stagnation counters when the pipeline advances.
        self._prev_phase: PipelinePhase | None = None
        # Mentor supervision: counts individual tool executions since last
        # mentor analysis injection (throttle: every 3 tools OR HIGH/CRITICAL).
        self._mentor_tool_call_count: int = 0
        # When set, force the next response(s) to include a tool call after
        # recovery events (VRAM crash/timeout). Prevents text-only hallucinations.
        self._recovery_force_tool_calls: int = 0
        self._session: SessionData | None = None
        self._pending_output_merges: dict[str, list[str]] = {}
        self._blocked_tools: set[str] = set()
        self._session_lock = asyncio.Lock()
        # If set, overrides config in process_message
        self._override_max_iterations: int | None = None
        self._ctf_mode: bool = False  # True when target is CTF/XBOW/localhost
        # True for subagents — skips AIRECON_SESSION_ID env var so subagent
        # never loads or overwrites the parent's persisted session.
        self._is_subagent: bool = False
        self.pipeline: PipelineEngine | None = None
        # Tracks skill rel-paths already injected via tech-skill loader so
        # the same skill file isn't injected again when the same technology
        # is re-detected in later tool outputs.
        self._loaded_tech_skill_paths: set[str] = set()
        # Session-persistent context window — set on first VRAM crash and kept
        # for all subsequent iterations so the same crash doesn't recur.
        # 0 means "use config default".
        self._adaptive_num_ctx: int = 0
        # Total VRAM OOM crashes across the entire session — used to escalate
        # truncation aggressiveness on each successive crash.
        self._vram_crash_count: int = 0
        # Output token cap — set after VRAM crash to prevent large responses
        # from burning context and re-triggering OOM. 0 = no cap.
        self._adaptive_num_predict_cap: int = 0
        # Async token snapshot persistence (coalesced) to avoid blocking the
        # main event loop on every completion.
        self._token_snapshot_task: asyncio.Task[None] | None = None
        self._token_snapshot_resave_requested: bool = False
        # Accumulated iterative compression summary (AIRecon-style).
        # Updated each time _enforce_char_budget triggers LLM compression.
        # On re-compression the prior summary is included so the LLM can
        # PRESERVE + ADD rather than summarising from scratch.
        self._compression_summary: str = ""
        # Budget pressure cascade level (0=none, 1=70%, 2=85%, 3=95%, 4=forced REPORT).
        # Each threshold fires exactly once per session.
        self._budget_pressure_level: int = 0

    async def stop(self) -> None:
        """Stop agent loop and save session."""
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True
        
        if self._session and self._session.target:
            try:
                logger.info("Saving session data (subdomains: %d, live_hosts: %d, vulns: %d)...",
                           len(self._session.subdomains),
                           len(self._session.live_hosts),
                           len(self._session.vulnerabilities))
                
                self._sync_token_usage_to_session()
                self._sync_recovery_state_to_session()
                
                async with self._session_lock:
                    from .session import save_session
                    save_session(self._session)
                logger.info("Session saved to ~/.airecon/sessions/%s.json",
                           self._session.session_id)
            except Exception as e:
                logger.error("Failed to save session during stop: %s", e)
        
        if self.engine:
            await self.engine.force_stop()
        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_resave_requested = True
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._token_snapshot_task),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                logger.debug("Token snapshot flush timed out — cancelling task.")
                self._token_snapshot_task.cancel()
                try:
                    await self._token_snapshot_task
                except (asyncio.CancelledError, Exception):
                    pass
            except Exception:
                logger.debug("Token snapshot flush skipped during stop.")

    def _sync_token_usage_from_session(self) -> None:
        """Hydrate state token counters from current persisted session."""
        if not self._session:
            return
        usage = self.state.token_usage
        usage["cumulative"] = int(getattr(self._session, "token_total", 0) or 0)
        usage["cumulative_prompt"] = int(
            getattr(self._session, "token_prompt_total", 0) or 0
        )
        usage["cumulative_completion"] = int(
            getattr(self._session, "token_completion_total", 0) or 0
        )
        usage["used"] = 0
        usage["last_prompt"] = 0
        usage["last_completion"] = 0

    def _sync_token_usage_to_session(self) -> None:
        """Persist token counters into session so restart/recovery keeps totals."""
        if not self._session:
            return
        usage = self.state.token_usage
        self._session.token_total = int(usage.get("cumulative", 0) or 0)
        self._session.token_prompt_total = int(
            usage.get("cumulative_prompt", 0) or 0
        )
        self._session.token_completion_total = int(
            usage.get("cumulative_completion", 0) or 0
        )
        self._session.token_last_used = int(usage.get("used", 0) or 0)
        self._sync_recovery_state_to_session()

    def _sync_recovery_state_from_session(self) -> None:
        """Hydrate adaptive recovery state from persisted session."""
        if not self._session:
            return
        sess_ctx = int(getattr(self._session, "adaptive_num_ctx", 0) or 0)
        sess_cap = int(getattr(self._session, "adaptive_num_predict_cap", 0) or 0)
        sess_crashes = int(getattr(self._session, "vram_crash_count", 0) or 0)

        if sess_ctx > 0:
            if self._adaptive_num_ctx > 0:
                self._adaptive_num_ctx = min(self._adaptive_num_ctx, sess_ctx)
            else:
                self._adaptive_num_ctx = sess_ctx

        if sess_cap > 0:
            self._adaptive_num_predict_cap = sess_cap

        if self._adaptive_num_ctx > 0 and self._adaptive_num_predict_cap > 0:
            self._adaptive_num_predict_cap = min(
                self._adaptive_num_predict_cap,
                max(512, self._adaptive_num_ctx // 4),
            )

        self._vram_crash_count = max(self._vram_crash_count, sess_crashes)

    def _sync_recovery_state_to_session(self) -> None:
        """Persist adaptive recovery state into session."""
        if not self._session:
            return
        self._session.adaptive_num_ctx = max(0, int(self._adaptive_num_ctx or 0))
        self._session.adaptive_num_predict_cap = max(
            0, int(self._adaptive_num_predict_cap or 0)
        )
        self._session.vram_crash_count = max(0, int(self._vram_crash_count or 0))

    def _has_scan_work(self) -> bool:
        """Return True if the current session has done actual scanning work.

        Prevents empty sessions (user asked a question containing a domain
        name but no tools were ever run) from being written to disk.
        """
        if not self._session:
            return False
        return self._session.scan_count > 0 or bool(self.state.evidence_log)

    def _schedule_token_usage_snapshot_save(self) -> None:
        """Persist token snapshot asynchronously while coalescing bursts."""
        session = self._session
        if not session or not session.target:
            return

        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_resave_requested = True
            return

        self._token_snapshot_resave_requested = False

        async def _save_worker(initial_session: SessionData) -> None:
            session_to_save: SessionData | None = initial_session
            try:
                while session_to_save and session_to_save.target:
                    try:
                        async with self._session_lock:
                            await asyncio.to_thread(save_session, session_to_save)
                    except Exception as exc:
                        logger.debug("Failed to persist token usage snapshot: %s", exc)
                    if not self._token_snapshot_resave_requested:
                        break
                    self._token_snapshot_resave_requested = False
                    session_to_save = self._session
            finally:
                self._token_snapshot_task = None

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                # No running event loop: asyncio.Lock cannot be acquired here.
                # Best effort save if lock is not currently held by an async task.
                if not self._session_lock.locked():
                    save_session(session)
                else:
                    logger.debug("Session save skipped - lock held")
            except Exception as exc:
                logger.debug("Failed to persist token usage snapshot: %s", exc)
            return

        self._token_snapshot_task = loop.create_task(_save_worker(session))

    def _record_token_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Record latest usage and accumulate session totals."""
        prompt_tokens = max(0, int(prompt_tokens or 0))
        completion_tokens = max(0, int(completion_tokens or 0))
        total_tokens = prompt_tokens + completion_tokens
        if total_tokens <= 0:
            return

        usage = self.state.token_usage
        usage["used"] = total_tokens
        usage["last_prompt"] = prompt_tokens
        usage["last_completion"] = completion_tokens
        usage["cumulative"] = int(usage.get("cumulative", 0) or 0) + total_tokens
        usage["cumulative_prompt"] = int(
            usage.get("cumulative_prompt", 0) or 0
        ) + prompt_tokens
        usage["cumulative_completion"] = int(
            usage.get("cumulative_completion", 0) or 0
        ) + completion_tokens
        self._sync_token_usage_to_session()
        self._schedule_token_usage_snapshot_save()

    # ------------------------------------------------------------------
    # Anti-repeat guard (Priority 2)
    # ------------------------------------------------------------------

    def _is_duplicate_command(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[bool, str]:
        """Return (is_duplicate, explanation_message).

        Uses MD5 hash of (tool_name + canonical JSON args) to detect
        identical tool calls across all iterations.  Safe to call on every
        tool invocation; exempt tools and interactive browser actions bypass
        the check entirely.
        """
        # Exempt: stateful / side-effect tools that must always run
        if tool_name in self._DEDUP_EXEMPT_TOOLS:
            return False, ""

        # Exempt: interactive browser actions
        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in self._DEDUP_EXEMPT_BROWSER_ACTIONS:
                return False, ""

        # Normalise args: sort keys, strip leading/trailing whitespace from
        # string values
        def _normalise(v: Any) -> Any:
            if isinstance(v, str):
                return v.strip()
            return v

        try:
            canonical = json.dumps(
                {k: _normalise(v) for k, v in args.items()}, sort_keys=True
            )
        except (TypeError, ValueError):
            canonical = str(args)

        # Include current phase in the hash so the same command can be re-run
        # when the pipeline transitions (e.g. RECON → ANALYSIS → EXPLOIT).
        # Without phase context, legitimate retests (e.g. re-running sqlmap
        # after auth changes in EXPLOIT) are incorrectly blocked.
        try:
            _phase_ctx = self._get_current_phase().value
        except Exception:
            _phase_ctx = "unknown"
        raw = f"{_phase_ctx}:{tool_name}:{canonical}"
        cmd_hash = hashlib.md5(  # nosec B324 - non-security dedup hash
            raw.encode(
                "utf-8",
                errors="replace"),
            usedforsecurity=False).hexdigest()

        if cmd_hash in self._executed_cmd_hashes:
            msg = (
                f"[ANTI-REPEAT] Command '{tool_name}' with identical arguments was already "
                "executed. The result is already in your tool history. "
                "Do NOT repeat it — use the existing result and proceed to the next step."
            )
            return True, msg

        self._executed_cmd_hashes.add(cmd_hash)
        
        # FIX #6 (Medium): Incremental pruning to prevent memory growth
        # Old behavior: clear() all when >5000 (causes re-execution of old commands)
        # New behavior: prune oldest 2500 when >5000 (preserves recent history)
        # This prevents memory bloat while maintaining dedup effectiveness.
        if len(self._executed_cmd_hashes) > 5000:
            # Convert to list, keep newest 2500 entries (FIFO pruning)
            entries = list(self._executed_cmd_hashes)
            if len(entries) > 2500:
                # Keep the most recent 2500 entries
                self._executed_cmd_hashes = set(entries[-2500:])
                logger.debug(
                    "_executed_cmd_hashes incrementally pruned: %d → %d entries (kept newest 2500)",
                    len(entries), len(self._executed_cmd_hashes)
                )
        
        return False, ""

    async def initialize(
        self,
        target: str | None = None,
        user_message: str | None = None,
    ) -> None:
        self.state.conversation = [
            {"role": "system", "content": get_system_prompt(
                target=target, user_message=user_message)}
        ]
        # Detect CTF mode early so process_message can apply iteration cap
        if _is_ctf_target(target, user_message):
            self._ctf_mode = True
            if self._override_max_iterations is None:
                self._override_max_iterations = self._CTF_MAX_ITERATIONS
            # Use smaller context window in CTF mode to prevent VRAM OOM.
            # KV cache for qwen3.5:122b @ 131072 ctx ≈ 31 GB extra VRAM.
            # ollama_num_ctx_small (default 32768) cuts that to ~8 GB.
            _ctf_cfg = get_config()
            if self._adaptive_num_ctx == 0:
                self._adaptive_num_ctx = _ctf_cfg.ollama_num_ctx_small
            logger.info(
                "CTF mode activated for target=%r — ctx=%d, max_iterations=%d",
                target, self._adaptive_num_ctx, self._CTF_MAX_ITERATIONS,
            )
        engine_tools = await self.engine.discover_tools()
        self._tools_ollama = self.engine.tools_to_ollama_format(engine_tools)

        if self.engine:
            self.state.add_message(
                "system", "[SYSTEM: EXECUTE_COMMAND_AVAILABLE=yes]")

        # Probe Caido availability — non-blocking (5s timeout, returns None if down).
        # This gives the model a binary signal it can act on immediately, mirroring
        # the EXECUTE_COMMAND_AVAILABLE pattern.
        from ..caido_client import CaidoClient
        _caido_token = await CaidoClient._get_token()
        self._caido_available: bool = bool(_caido_token)
        if _caido_token:
            self.state.add_message(
                "system",
                "[SYSTEM: CAIDO_PROXY=available port=48080] "
                "Caido web proxy is running and capturing ALL HTTP traffic automatically. "
                "Call caido_list_requests NOW (no scope setup needed) to retrieve captured "
                "requests — this reveals real app endpoints, auth flows, cookies, hidden "
                "parameters, and injection points that active scanning cannot find. "
                "After reviewing captured requests, use caido_set_scope to focus future "
                "captures, then periodically call caido_list_requests to check for new traffic."
            )
        else:
            self.state.add_message(
                "system",
                "[SYSTEM: CAIDO_PROXY=unavailable] "
                "Caido is not running — do NOT call caido_* tools."
            )

        if self._tools_ollama is None:
            self._tools_ollama = []
        self._tools_ollama.extend(get_tool_definitions())

        # Deduplicate by tool name
        unique: dict[str, dict] = {}
        for t in self._tools_ollama:
            unique[t["function"]["name"]] = t
        self._tools_ollama = list(unique.values())

        # Remove blocked tools (e.g. spawn_agent blocked for subagents to
        # prevent recursion)
        if self._blocked_tools:
            self._tools_ollama = [
                t for t in self._tools_ollama
                if t["function"]["name"] not in self._blocked_tools
            ]

        logger.info("Agent initialized with %d tools", len(self._tools_ollama))

        tool_names = [t["function"]["name"] for t in self._tools_ollama]
        self.state.add_message(
            "system", f"[SYSTEM: REGISTERED TOOLS]\n{', '.join(tool_names)}"
        )

        self._initial_messages = list(self.state.conversation)

        # Initialize session: load from env var ID if provided, otherwise
        # create fresh.  Subagents always get a fresh session so they never
        # load or overwrite the parent agent's persisted session data.
        _session_id = os.environ.get("AIRECON_SESSION_ID") if not self._is_subagent else None
        if _session_id:
            self._session = load_session(_session_id) or SessionData(
                session_id=_session_id, target=""
            )
            logger.info("Loaded session %s (target=%s)", _session_id, self._session.target)
        else:
            self._session = SessionData(target="")
            logger.info("Created new session %s", self._session.session_id)
        self._sync_recovery_state_from_session()
        self._sync_token_usage_from_session()

        self.pipeline = PipelineEngine(self._session)
        if self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)

    def reset(self) -> None:
        # Cancel any in-flight token snapshot from the old session.
        # reset() is sync, so we call cancel() (schedules CancelledError on the
        # task) rather than awaiting — the task's finally block will still run.
        if self._token_snapshot_task and not self._token_snapshot_task.done():
            self._token_snapshot_task.cancel()
        self._token_snapshot_task = None
        self._token_snapshot_resave_requested = False
        self.state = AgentState()
        if self._initial_messages:
            self.state.conversation = list(self._initial_messages)
        self._executed_tool_counts.clear()
        self._executed_cmd_hashes.clear()
        self._last_output_file = None
        self._stagnation_iterations = 0
        self._recent_tool_names.clear()
        self._last_evidence_count = 0
        self._watchdog_forced_calls = 0
        self._adaptive_num_ctx = 0
        self._vram_crash_count = 0
        self._adaptive_num_predict_cap = 0
        # Create a new session on reset (keeps the old one on disk)
        self._session = SessionData(target="")
        self.pipeline = PipelineEngine(self._session)
        if self._ctf_mode and self.pipeline:
            self.pipeline.set_ctf_mode(True)

    def _skill_phase_for_message_start(self) -> str:
        """Return phase hint for initial skill auto-loading on user message."""
        try:
            return self._get_current_phase().value
        except Exception:
            return "RECON"

    async def process_message(
            self, user_message: str) -> AsyncIterator[AgentEvent]:
        try:
            # ── Strip @/path refs BEFORE target extraction ────────────────
            # Prevents filenames like @/tmp/app.com or @/tmp/evil.com from
            # being mistakenly detected as domain/IP targets by the regex.
            # workspace/<target>/ ← IP/domain (from clean message)
            # workspace/<stem>/   ← file stem (fallback when no target)
            # workspace/<dir>/    ← dir name (fallback when no target)
            _file_refs = parse_refs(user_message)
            if _file_refs:
                user_message = strip_refs(user_message, _file_refs)

            all_targets = self._extract_targets_from_text(user_message)
            extracted_target = all_targets[0] if all_targets else None

            if not self._tools_ollama:
                # First call: initialise with target+message so CTF prompt is
                # selected
                await self.initialize(
                    target=extracted_target,
                    user_message=user_message,
                )
            else:
                # Subsequent messages: re-check CTF only against the new
                # target URL — NOT the message body.  Passing user_message
                # here caused false positives when the LLM's own output
                # (or the user's follow-up) contained security terms like
                # "flag", "challenge", or "benchmark" during a normal recon.
                if not self._ctf_mode and extracted_target:
                    if _is_ctf_target(extracted_target, user_message=None):
                        self._ctf_mode = True
                        if self._override_max_iterations is None:
                            self._override_max_iterations = self._CTF_MAX_ITERATIONS
                        if self.pipeline:
                            self.pipeline.set_ctf_mode(True)
                        # Reduce context window to prevent VRAM OOM mid-session
                        if self._adaptive_num_ctx == 0:
                            self._adaptive_num_ctx = get_config().ollama_num_ctx_small
                        logger.info(
                            "CTF mode activated mid-session for target=%r — ctx=%d",
                            extracted_target, self._adaptive_num_ctx,
                        )

            if extracted_target:
                # Don't switch workspace when the new target is a subdomain of
                # the current active target.  Subdomain results belong under the
                # parent domain's workspace so we don't scatter output into
                # separate top-level folders (e.g. app.example.com/ next to
                # example.com/).
                _current = self.state.active_target
                _is_subdomain = bool(
                    _current
                    and extracted_target != _current
                    and extracted_target.endswith("." + _current)
                )
                if not _is_subdomain:
                    self.state.active_target = extracted_target

            cfg = get_config()

            # Set workspace from file ref if no IP/domain was detected.
            # workspace/challenge/  ← @/tmp/challenge.exe (stem)
            # workspace/project1/   ← @/path/project1/   (dir name)
            # workspace/192.168.1.1/ kept when IP/domain target already set.
            if _file_refs and not self.state.active_target:
                self.state.active_target = workspace_name_for_ref(
                    _file_refs[0]
                )

            _COMPLEX_SIGNALS = (
                "how", "what", "why", "explain", "show me", "list", "help",
                "?", "can you", "could you", "please tell", "describe",
            )
            _msg_lower = user_message.strip().lower()
            _is_simple_target_msg = (
                extracted_target is not None
                and len(user_message.strip()) <= 120
                and not any(s in _msg_lower for s in _COMPLEX_SIGNALS)
                and extracted_target.lower() in _msg_lower
            )
            if cfg.deep_recon_autostart and _is_simple_target_msg:
                logger.info("Auto-starting deep recon for %s", extracted_target)
                user_message = (
                    f"Perform a comprehensive full deep recon and "
                    f"vulnerability scan on {extracted_target}. "
                    "Use all available tools."
                )

            EPHEMERAL_PREFIXES = (
                "[SYSTEM: WORKSPACE",
                "[SYSTEM: ACTIVE_TARGET",
                "[SYSTEM: ADDITIONAL_TARGETS",
                "[SYSTEM: OBJECTIVE FOCUS",  # legacy
                "<objective_focus",           # XML format
                "[SYSTEM: PHASE GATE",
                "[SYSTEM: AGGRESSIVE EXPLORATION",
                "[SYSTEM: QUALITY SCOREBOARD",
                "[SYSTEM: RECOVERY STATE",
                "<reflector ",               # XML reflector
                "<mentor_analysis>",         # XML mentor
            )
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not (
                    msg.get("role") == "system"
                    and any(
                        msg.get("content", "").startswith(p) for p in EPHEMERAL_PREFIXES
                    )
                )
            ]

            if len(all_targets) > 1:
                extra = ", ".join(all_targets[1:])
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": (
                            f"[SYSTEM: ADDITIONAL_TARGETS={extra}] "
                            f"Primary workspace is '{extracted_target}'. "
                            f"Additional targets also mentioned: {extra}. "
                            "Handle each in sequence or as directed by the user."
                        ),
                    }
                )

            if self.state.active_target:
                workspace_context = await asyncio.to_thread(
                    self._scan_workspace_state, self.state.active_target
                )
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": workspace_context
                        if workspace_context
                        else f"[SYSTEM: ACTIVE_TARGET={self.state.active_target}]",
                    }
                )

                # Update session target (session was pre-created in
                # initialize())
                if not self._session:
                    self._session = SessionData(
                        target=self.state.active_target)
                    self._sync_token_usage_from_session()
                    self.pipeline = PipelineEngine(self._session)
                    if self._ctf_mode and self.pipeline:
                        self.pipeline.set_ctf_mode(True)
                elif self._session.target != self.state.active_target:
                    # Target switched mid-session — create a fresh SessionData
                    # to prevent old target's subdomains/urls/findings from
                    # contaminating the new target's context.
                    logger.info(
                        "Target switched %s → %s: creating fresh SessionData",
                        self._session.target,
                        self.state.active_target,
                    )
                    self._session = SessionData(
                        target=self.state.active_target)
                    self._sync_token_usage_from_session()
                    self.pipeline = PipelineEngine(self._session)
                    if self._ctf_mode and self.pipeline:
                        self.pipeline.set_ctf_mode(True)

                # Cross-session memory: pre-populate new session with findings
                # from the most recent prior scan of the same target so the
                # agent doesn't re-discover already-known subdomains/ports/URLs.
                # Only runs once per session (scan_count == 0 → brand new session).
                if (
                    self._session
                    and self._session.scan_count == 0
                    and not getattr(self._session, "_prior_merged", False)
                ):
                    prior = find_prior_session(self.state.active_target)
                    if prior and prior.session_id != self._session.session_id:
                        merge_prior_findings(self._session, prior)
                        # Inject a brief context note so the LLM knows what's pre-loaded
                        _prior_ctx = (
                            f"[PRIOR SESSION MEMORY] Loaded {len(prior.subdomains)} subdomains, "
                            f"{len(prior.urls)} URLs, {len(prior.injection_points)} injection points "
                            f"from previous scan of {self.state.active_target} "
                            f"(session {prior.session_id}). "
                            "This data is pre-populated in your session — no need to rediscover them. "
                            "Focus on new coverage and deeper exploitation."
                        )
                        self.state.conversation.append(
                            {"role": "system", "content": _prior_ctx}
                        )
                        logger.info(
                            "Cross-session memory: merged prior session %s → %s",
                            prior.session_id, self._session.session_id,
                        )
                    # Mark as merged (even if no prior found) to prevent re-running
                    self._session._prior_merged = True

                if self._session and self._session.scan_count > 0:
                    session_ctx = session_to_context(self._session)
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": session_ctx,
                        }
                    )
                    # Pre-mark phase objectives as done based on existing session
                    # data so the LLM knows which RECON/ANALYSIS steps are already
                    # complete and doesn't repeat them.
                    if self.pipeline:
                        _resumed_phase = self.pipeline.get_current_phase()
                        self._sync_phase_objectives(_resumed_phase)
                        self._update_objectives_from_session(_resumed_phase)

            # Ensure a compact, pinned target context is always present so the
            # model never loses the primary target during long sessions.
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not (
                    msg.get("role") == "system"
                    and msg.get("content", "").startswith("[SYSTEM: PINNED CONTEXT]")
                )
            ]
            if self.state.active_target:
                phase_hint = ""
                try:
                    if self.pipeline:
                        phase_hint = self.pipeline.get_current_phase().value
                except Exception:
                    phase_hint = ""
                pin_lines = [
                    "[SYSTEM: PINNED CONTEXT]",
                    f"TARGET: {self.state.active_target}",
                ]
                if phase_hint:
                    pin_lines.append(f"PHASE: {phase_hint}")
                pin_lines.append("Do not change target unless the user explicitly asks.")
                pin_lines.append("Use session summary and critical findings as the source of truth.")
                self.state.conversation.append(
                    {"role": "system", "content": "\n".join(pin_lines)}
                )

            # Resolve @/path file references (parsed earlier, before autostart)
            if _file_refs:
                _workspace_root = get_workspace_root().resolve()
                _workspace_dir = (
                    _workspace_root / (self.state.active_target or "uploads")
                ).resolve()
                try:
                    _workspace_dir.relative_to(_workspace_root)
                except ValueError:
                    logger.warning(
                        "Blocked unsafe workspace target %r for file refs; using fallback uploads/",
                        self.state.active_target,
                    )
                    _workspace_dir = _workspace_root / "uploads"
                _resolved = await asyncio.to_thread(
                    lambda: [resolve_ref(r, _workspace_dir) for r in _file_refs]
                )
                _injection = build_injection_message(_resolved)
                if _injection:
                    self.state.conversation.append(
                        {"role": "system", "content": _injection}
                    )

            self.state.conversation.append(
                {"role": "user", "content": user_message})

            # Auto-load relevant skills based on user message keywords.
            # Use current phase (important for resumed sessions), fallback RECON.
            _skill_phase = self._skill_phase_for_message_start()
            # Pass session.loaded_skills for dedup (prevent re-loading same skills)
            _session_skills = None
            if self._session:
                _session_skills = set(self._session.loaded_skills)
            skill_context, loaded_skills = auto_load_skills_for_message(
                user_message,
                phase=_skill_phase,
                session_loaded_skills=_session_skills,
            )
            if loaded_skills:
                for s in loaded_skills:
                    _skill_name = Path(str(s)).stem
                    if _skill_name not in self.state.skills_used:
                        self.state.skills_used.append(_skill_name)
                # Track loaded skills in session for dedup across messages
                if self._session:
                    for skill_rel in loaded_skills:
                        if skill_rel not in self._session.loaded_skills:
                            self._session.loaded_skills.append(skill_rel)

            if skill_context:
                # Tag skill messages with iteration for _prune_stale_skills to work correctly
                self.state.conversation.append(
                    {"role": "system", "content": skill_context, "iteration": self.state.iteration}
                )

            # Reset per-message state
            self.state.iteration = 0
            self.state.max_iterations = (
                self._override_max_iterations
                or cfg.agent_max_tool_iterations
                or MAX_TOOL_ITERATIONS
            )
            self.state.warnings_sent = False
            self._stop_requested = False
            self._consecutive_failures = 0
            self._mentor_tool_call_count = 0
            self._no_tool_iterations = 0
            self._stagnation_iterations = 0
            self._recent_tool_names = []
            self._last_evidence_count = sum(
                1 for e in self.state.evidence_log
                if e.get("confidence", 0) >= _MEANINGFUL_EVIDENCE_THRESHOLD
            )
            self._watchdog_forced_calls = 0
            self._empty_response_retry_count = 0
            self._prev_phase = None
            # NOTE: Do NOT clear _executed_tool_counts here — dedup must persist
            # across messages within the same session. It is only cleared in
            # reset().

            # Follow-up after TASK_COMPLETE: reset pipeline and clear stale state
            # so the model doesn't inherit old REPORT-phase objectives when the
            # user asks for a new focused task (e.g., "focus on XSS").
            if (
                self._session
                and getattr(self._session, "current_phase", "") == "COMPLETE"
                and self.pipeline
            ):
                self.pipeline.set_phase(PipelinePhase.RECON)
                self.state.objective_queue.clear()
                # Compact evidence_log: keep only high-confidence findings so
                # follow-up context isn't flooded with noise from the prior scan.
                _HC_THRESHOLD = 0.8
                self.state.evidence_log = [
                    e for e in self.state.evidence_log
                    if e.get("confidence", 0) >= _HC_THRESHOLD
                ][-30:]
                self._last_evidence_count = len(self.state.evidence_log)
                logger.info(
                    "Follow-up after TASK_COMPLETE: phase reset to RECON, "
                    "objective_queue cleared, evidence_log compacted to %d entries.",
                    len(self.state.evidence_log),
                )

            while self.state.iteration < self.state.max_iterations:
                if self._stop_requested:
                    yield AgentEvent(
                        type="error", data={"message": "Agent stopped by user."}
                    )
                    yield AgentEvent(type="done", data={})
                    return

                self.state.increment_iteration()
                current_phase = self._get_current_phase()

                # ── BUDGET PRESSURE CASCADE ──────────────────────────────────
                # As the agent approaches MAX_TOOL_ITERATIONS, inject escalating
                # urgency messages so it prioritises and consolidates findings
                # rather than discovering indefinitely.  Each threshold fires once.
                _budget_ratio = self.state.iteration / max(self.state.max_iterations, 1)
                if _budget_ratio >= 1.0 and self._budget_pressure_level < 4:
                    self._budget_pressure_level = 4
                    logger.warning(
                        "Budget exhausted at iteration %d/%d — forcing REPORT phase.",
                        self.state.iteration, self.state.max_iterations,
                    )
                    if self.pipeline and current_phase.value != "REPORT":
                        self.pipeline.set_phase(PipelinePhase.REPORT)
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: BUDGET EXHAUSTED] You have used all available "
                            "iterations. STOP all testing immediately. Your ONLY task "
                            "now is to call the report tool and write the final report "
                            "with everything you have found."
                        ),
                    })
                elif _budget_ratio >= 0.95 and self._budget_pressure_level < 3:
                    self._budget_pressure_level = 3
                    remaining = self.state.max_iterations - self.state.iteration
                    logger.info(
                        "Budget pressure L3 (95%%) at iteration %d, %d remaining.",
                        self.state.iteration, remaining,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            f"[SYSTEM: BUDGET CRITICAL — {remaining} iterations left] "
                            "STOP all new discovery. You must now: (1) call the report "
                            "tool with all confirmed findings, (2) advance to REPORT "
                            "phase if not already there. No more scanning or fuzzing."
                        ),
                    })
                elif _budget_ratio >= 0.85 and self._budget_pressure_level < 2:
                    self._budget_pressure_level = 2
                    remaining = self.state.max_iterations - self.state.iteration
                    logger.info(
                        "Budget pressure L2 (85%%) at iteration %d, %d remaining.",
                        self.state.iteration, remaining,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            f"[SYSTEM: BUDGET WARNING — {remaining} iterations left] "
                            "Begin consolidating findings for the report. Finish any "
                            "in-progress tests, then switch to REPORT phase. Do not "
                            "start new discovery chains."
                        ),
                    })
                elif _budget_ratio >= 0.70 and self._budget_pressure_level < 1:
                    self._budget_pressure_level = 1
                    remaining = self.state.max_iterations - self.state.iteration
                    logger.info(
                        "Budget pressure L1 (70%%) at iteration %d, %d remaining.",
                        self.state.iteration, remaining,
                    )
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            f"[SYSTEM: BUDGET NOTICE — {remaining} iterations left] "
                            "Prioritise your highest-value untested attack vectors only. "
                            "Avoid retrying already-tested paths or broad enumeration."
                        ),
                    })

                # Reset stagnation counters on phase transition so ANALYSIS/
                # EXPLOIT don't start with an inflated stagnation count inherited
                # from the previous phase — that would trigger aggressive
                # exploration immediately after transition.
                if self._prev_phase is not None and current_phase != self._prev_phase:
                    logger.debug(
                        "Phase transition %s → %s: stagnation counter reset.",
                        self._prev_phase.value,
                        current_phase.value,
                    )
                    self._stagnation_iterations = 0
                    self._recent_tool_names.clear()
                self._prev_phase = current_phase

                self._sync_phase_objectives(current_phase)
                self._update_objectives_from_session(current_phase)

                # Inject objective focus + quality scoreboard:
                # - CTF mode: only when genuinely stuck (no_tool_iterations >= 2)
                #   to avoid flooding thinking models with system noise every iteration.
                # - Normal mode: every 10 iterations or when stuck.
                _focus_trigger = (
                    self._no_tool_iterations >= 2
                    or (not self._ctf_mode and (
                        self.state.iteration == 1
                        or self.state.iteration % 10 == 0
                    ))
                )
                if _focus_trigger:
                    self.state.conversation = [
                        msg
                        for msg in self.state.conversation
                        if not (
                            msg.get("content", "").startswith("[SYSTEM: OBJECTIVE FOCUS")
                            or msg.get("content", "").startswith("<objective_focus")
                        )
                    ]
                    focus_ctx = self.state.build_focus_context(
                        current_phase.value,
                        max_objectives=4,
                        max_evidence=6,
                    )
                    if focus_ctx:
                        self.state.conversation.append(
                            {"role": "system", "content": focus_ctx}
                        )

                    # Quality scoreboard: skip in CTF mode entirely (noise vs value).
                    if not self._ctf_mode:
                        self.state.conversation = [
                            msg
                            for msg in self.state.conversation
                            if not msg.get("content", "").startswith(
                                "[SYSTEM: QUALITY SCOREBOARD"
                            )
                        ]
                        quality_ctx = self._build_quality_scoreboard(current_phase)
                        if quality_ctx:
                            self.state.conversation.append(
                                {"role": "system", "content": quality_ctx}
                            )

                    # Hypothesis Engine: auto-resolve confirmed hypotheses from
                    # evidence, then inject pending hypotheses context.
                    # Run on every focus trigger so the LLM always knows what to
                    # test next and never re-tests a refuted hypothesis.
                    self.state.resolve_hypotheses_from_evidence()
                    self.state.conversation = [
                        msg for msg in self.state.conversation
                        if not msg.get("content", "").startswith("<hypothesis_queue")
                    ]
                    hyp_ctx = self.state.build_hypothesis_context(max_pending=4)
                    if hyp_ctx:
                        self.state.conversation.append(
                            {"role": "system", "content": hyp_ctx}
                        )

                    # Exploit Chain Planner: plan chains from confirmed vulns in
                    # EXPLOIT phase. Also includes confirmed hypotheses as synthetic
                    # vulnerabilities so hypothesis-driven findings can spawn chains
                    # even before the session vulnerability list is populated.
                    _confirmed_hyp_vulns: list[dict[str, Any]] = [
                        {
                            "finding": h.get("claim", ""),
                            "type": next(iter(h.get("tags", ["unknown"])), "unknown"),
                            "severity": "HIGH",
                            "proof": "; ".join(
                                str(r) for r in h.get("evidence_refs", [])
                            )[:200],
                        }
                        for h in self.state.hypothesis_queue
                        if h.get("status") == "confirmed"
                    ]
                    _session_vulns = (
                        list(self._session.vulnerabilities) if self._session else []
                    )
                    _all_vulns_for_chains = _session_vulns + _confirmed_hyp_vulns
                    if current_phase.value == "EXPLOIT" and _all_vulns_for_chains:
                        try:
                            _existing_ids = {
                                str(c.get("chain_id", ""))
                                for c in self.state.exploit_chains
                            }
                            _new_chains = plan_chains(
                                vulnerabilities=_all_vulns_for_chains,
                                existing_chain_ids=_existing_ids,
                                iteration=self.state.iteration,
                                max_chains=3,
                                causal_hypotheses=[
                                    h.__dict__
                                    for h in getattr(
                                        getattr(self._session, "causal_state", None),
                                        "hypotheses",
                                        [],
                                    )
                                ],
                            )
                            for _nc in _new_chains:
                                # Serialise ExploitChain to dict for state storage
                                self.state.exploit_chains.append(_asdict(_nc))
                                logger.info(
                                    "Exploit chain planned: %s (basis: %s)",
                                    _nc.name, _nc.vuln_basis[:60],
                                )
                            # Inject chain context
                            _ec_objs: list[_ExploitChain] = []
                            for _cd in self.state.exploit_chains:
                                try:
                                    # Re-hydrate from dict for build_chain_context
                                    _steps = [
                                        _ChainStep(**s) if isinstance(s, dict) else s
                                        for s in _cd.get("steps", [])
                                    ]
                                    _chain_obj = _ExploitChain(
                                        chain_id=str(_cd.get("chain_id", "")),
                                        name=str(_cd.get("name", "")),
                                        description=str(_cd.get("description", "")),
                                        steps=_steps,
                                        current_step_index=int(_cd.get("current_step_index", 0)),
                                        status=str(_cd.get("status", "planning")),
                                        phase_formed=str(_cd.get("phase_formed", "EXPLOIT")),
                                        vuln_basis=str(_cd.get("vuln_basis", "")),
                                        iteration_formed=int(_cd.get("iteration_formed", 0)),
                                    )
                                    _ec_objs.append(_chain_obj)
                                except Exception as _chain_hydrate_err:
                                    logger.debug("Chain hydration error: %s", _chain_hydrate_err)
                            chain_ctx = build_chain_context(_ec_objs, max_chains=2)
                            if chain_ctx:
                                self.state.conversation = [
                                    m for m in self.state.conversation
                                    if not m.get("content", "").startswith("<exploit_chain_plan>")
                                ]
                                self.state.conversation.append({
                                    "role": "system",
                                    "content": chain_ctx,
                                })
                        except Exception as _cp_err:
                            logger.debug("Chain planner error: %s", _cp_err)

                explore_ctx = self._build_exploration_directive(current_phase)
                if explore_ctx:
                    self.state.conversation = [
                        msg
                        for msg in self.state.conversation
                        if not msg.get("content", "").startswith(
                            "[SYSTEM: AGGRESSIVE EXPLORATION"
                        )
                    ]
                    self.state.conversation.append(
                        {"role": "system", "content": explore_ctx}
                    )

                # --- PLANNING INJECTION (iteration 1 only) ---
                if self.state.iteration == 1 and not self._ctf_mode:
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                "[SYSTEM: MANDATORY PLANNING STEP]\n"
                                "Write a brief, goal-oriented plan for your engagement.\n"
                                "Immediately execute the first step of Phase 1 (initial recon, scripts, OSINT) AFTER outputting your plan. Do not wait."
                            ),
                        }
                    )
                    # Clear planned tools at start
                    self.state.planned_tools.clear()

                # --- PLAN REVISION (every N iterations from config) ---
                revision_interval = cfg.agent_plan_revision_interval
                if (
                    not self._ctf_mode
                    and
                    revision_interval > 0
                    and self.state.iteration > 1
                    and self.state.iteration % revision_interval == 0
                ):
                    session_info = ""
                    if self._session:
                        s = self._session
                        session_info = (
                            f"\nCurrent findings: {len(s.subdomains)} subdomains, "
                            f"{len(s.live_hosts)} live hosts, "
                            f"{sum(len(p) for p in s.open_ports.values())} open ports, "
                            f"{len(s.urls)} URLs, "
                            f"{len(s.vulnerabilities)} vulnerabilities"
                        )
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                f"[SYSTEM: MANDATORY PLAN REVISION — iteration {self.state.iteration}]{session_info}\n"
                                "Your original plan may be stale. REVISED PLANNING REQUIRED:\n"
                                "1. Compare original plan vs actual findings\n"
                                "2. What has WORKED? What has FAILED?\n"
                                "3. Adjust strategy: which phases to SKIP, which to PRIORITIZE?\n"
                                "4. What is the single most valuable next action?\n"
                                "Output revised plan, then continue."
                            ),
                        }
                    )

                # --- PIPELINE CHECKPOINT (every 5 iterations) ---
                # Lightweight: injects pipeline phase prompt + session summary.
                # Correlation/chaining/expert run at every 10 (see below).
                if self.state.iteration > 1 and self.state.iteration % 5 == 0:
                    session_info = ""
                    pipeline_prompt = ""

                    if self._session:
                        s = self._session

                        # Keep pipeline iteration counter in sync
                        if self.pipeline:
                            self.pipeline._current_iteration = self.state.iteration

                        # Check pipeline transitions
                        if self.pipeline and self.pipeline.should_transition():
                            _prev_phase = self.pipeline.get_current_phase()
                            new_phase = self.pipeline.transition()
                            if new_phase:
                                pipeline_prompt = self.pipeline.get_transition_prompt(
                                    new_phase)
                                # Compact old phase context to reclaim KV cache space.
                                # Raw tool outputs from RECON are not needed verbatim
                                # in ANALYSIS; summaries + session state are sufficient.
                                self._compact_phase_context(
                                    _prev_phase.value if _prev_phase else "RECON"
                                )
                                # Pin confirmed vulnerabilities before EXPLOIT so they
                                # survive truncation and guide targeted exploitation.
                                from airecon.proxy.agent.pipeline import (
                                    PipelinePhase as _PP,
                                )
                                if new_phase == _PP.EXPLOIT:
                                    self._inject_exploit_vuln_context()
                                # New phase = fresh start for exploration pressure.
                                # Without this reset, stagnation accumulated in the
                                # previous phase inflates pressure in the new one,
                                # causing overly aggressive exploration from iter 1.
                                self._stagnation_iterations = 0
                                logger.debug(
                                    "Phase transition to %s — stagnation counter reset",
                                    new_phase.value,
                                )
                        elif self.pipeline:
                            pipeline_prompt = "\n" + self.pipeline.get_phase_prompt()

                        # In CTF mode keep checkpoint context compact to avoid
                        # token bloat and long-script loops. Include recent tool
                        # commands so the agent remembers what it already tried.
                        if self._ctf_mode:
                            _ctf_recent: list[str] = []
                            for _te in list(self.state.tool_history)[-6:]:
                                _cmd = ""
                                if getattr(_te, "tool_name", "") == "execute":
                                    _cmd = str(
                                        (_te.arguments or {}).get("command", "")
                                    )[:80]
                                elif getattr(_te, "tool_name", ""):
                                    _cmd = _te.tool_name
                                if _cmd:
                                    _rc = (
                                        (_te.result or {}).get("exit_code", "?")
                                        if isinstance(getattr(_te, "result", None), dict)
                                        else "?"
                                    )
                                    _ctf_recent.append(f"rc={_rc}: {_cmd}")
                            _tried_str = (
                                " | recent: " + "; ".join(_ctf_recent)
                                if _ctf_recent
                                else ""
                            )
                            session_info = (
                                "\n[CTF SESSION SUMMARY] "
                                f"urls={len(s.urls)} "
                                f"live_hosts={len(s.live_hosts)} "
                                f"injection_points={len(s.injection_points)} "
                                f"vulns={len(s.vulnerabilities)} "
                                f"tools={len(s.tools_run)}"
                                f"{_tried_str}"
                            )
                        else:
                            # Full session context injected to prevent "lost in the middle"
                            # context degradation in long runs. Includes actual finding data
                            # (subdomain list, host list, port map, tech stack, vuln titles)
                            # so the LLM doesn't need to recall from early
                            # conversation turns.
                            session_info = "\n" + session_to_context(s)
                            # Append ApplicationModel context when it has structural data
                            # (endpoints, auth map, roles, API schema from http_observe).
                            _app_ctx = s.app_model.build_context()
                            if _app_ctx:
                                session_info += "\n" + _app_ctx

                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": (
                                f"[SYSTEM: EXECUTION CHECKPOINT — Itr {self.state.iteration}]"
                                f"{session_info}\n\n"
                                f"{pipeline_prompt}"
                                "MANDATORY ACTION: Your NEXT response MUST be a tool call — NOT text, NOT a plan, NOT a code block. "
                                "Pick the highest-value next action and call the tool immediately. "
                                "Writing commands as text does nothing. Only tool calls execute. "
                                "If all objectives are complete, output [TASK_COMPLETE]."
                            ),
                        }
                    )

                # --- CTF MILESTONE SELF-AUDIT (at 33% and 66% of max iterations) ---
                # Forces the agent to reflect on what attack surfaces remain
                # unexplored — purely introspective, no vulnerability hints.
                if self._ctf_mode:
                    _max_itr = self._override_max_iterations or self._CTF_MAX_ITERATIONS
                    _m33 = max(5, _max_itr // 3)
                    _m66 = max(10, (_max_itr * 2) // 3)
                    if self.state.iteration in (_m33, _m66):
                        _pct = 33 if self.state.iteration == _m33 else 66
                        # _executed_tool_counts keys are (tool_name, phase) tuples
                        _tool_names_used = sorted({
                            k[0] for k in self._executed_tool_counts
                        })
                        _tools_str = (
                            ", ".join(_tool_names_used) if _tool_names_used else "none yet"
                        )
                        _recent_cmds: list[str] = []
                        for _te in list(self.state.tool_history)[-10:]:
                            if getattr(_te, "tool_name", "") == "execute":
                                _c = str((_te.arguments or {}).get("command", ""))[:100]
                                if _c:
                                    _recent_cmds.append(_c)
                        _recent_str = (
                            "\nRecent commands: " + " | ".join(_recent_cmds[-5:])
                            if _recent_cmds
                            else ""
                        )
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": (
                                    f"[SYSTEM: CTF STRATEGY AUDIT — {_pct}% of budget used]\n"
                                    f"Tools used so far: {_tools_str}"
                                    f"{_recent_str}\n"
                                    "Self-audit required:\n"
                                    "1. What attack surfaces / vulnerability classes have you NOT tested yet?\n"
                                    "2. What authentication mechanisms exist that you haven't probed?\n"
                                    "3. What data flows or state-changing endpoints are unexplored?\n"
                                    "4. Are there any cookie values, session tokens, or API responses you haven't analyzed?\n"
                                    "Based on your self-audit, pivot to the most promising UNTESTED attack class immediately. "
                                    "Reply with a tool call."
                                ),
                            }
                        )
                        logger.debug(
                            "CTF milestone self-audit injected at iteration %d (%d%% of %d)",
                            self.state.iteration,
                            _pct,
                            _max_itr,
                        )

                # --- EVALUATION CHECKPOINT (every 10 iterations) ---
                # Heavier: adds correlation, vuln chaining, expert testing
                # hints.
                if self.state.iteration > 1 and self.state.iteration % 10 == 0:
                    vuln_chaining_prompt = ""
                    correlation_prompt = ""
                    expert_testing_prompt = ""

                    if self._session:
                        s = self._session

                        # OUTPUT CORRELATION ENGINE
                        if s.open_ports or s.technologies or s.injection_points:
                            from ..correlation import (
                                run_correlation,  # lazy – avoids circular import
                            )
                            correlations = run_correlation(s)
                            if correlations:
                                corr_lines = [
                                    "\n[OUTPUT CORRELATION - Attack Surface Analysis]"]
                                for corr in correlations[:15]:
                                    severity = corr.get("severity", "MEDIUM")
                                    vuln_type = corr.get("type", "correlation")

                                    if vuln_type == "port":
                                        port = corr.get("port", "?")
                                        service = corr.get("service", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        tools = corr.get("tools", [])
                                        vuln_str = "; ".join(vulns[:2]) if vulns else "Multiple issues"
                                        tool_str = f" | tool: {tools[0]}" if tools else ""
                                        corr_lines.append(
                                            f"- [{severity}] Port {port} ({service}): {vuln_str}{tool_str}")

                                    elif vuln_type == "technology":
                                        tech = corr.get("technology", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        tools = corr.get("tools", [])
                                        paths = corr.get("paths", [])
                                        vuln_str = "; ".join(vulns[:2]) if vulns else "Multiple issues"
                                        extra = ""
                                        if tools:
                                            extra += f" | tool: {tools[0]}"
                                        if paths:
                                            extra += f" | paths: {', '.join(paths[:2])}"
                                        corr_lines.append(
                                            f"- [{severity}] Tech {tech}: {vuln_str}{extra}")

                                    elif vuln_type == "technology_cve":
                                        tech = corr.get("technology", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        vuln_str = vulns[0] if vulns else "Multiple issues"
                                        corr_lines.append(
                                            f"- [{severity}] {tech} CVE: {vuln_str}")

                                    elif vuln_type == "url_path":
                                        path = corr.get("path", "?")
                                        tech = corr.get("technology", "?")
                                        vulns = corr.get("vulnerabilities", [])
                                        tools = corr.get("tools", [])
                                        vuln_str = f": {vulns[0]}" if vulns else ""
                                        tool_str = f" | tool: {tools[0]}" if tools else ""
                                        corr_lines.append(
                                            f"- [{severity}] Path '{path}' → {tech}{vuln_str}{tool_str}")

                                    elif vuln_type == "injection_chain":
                                        inj_type = corr.get("injection_type", "?")
                                        chain_name = corr.get("chain_name", "?")
                                        count = corr.get("param_count", 0)
                                        params_sample = corr.get("sample_params", [])
                                        steps = corr.get("steps", [])
                                        steps_str = " → ".join(steps)
                                        params_str = ", ".join(params_sample) if params_sample else "discovered params"
                                        corr_lines.append(
                                            f"- [{severity}] INJECTION SURFACE ({inj_type}, "
                                            f"{count} params: {params_str}) → Chain: {chain_name}: {steps_str}")

                                    elif vuln_type == "expert_test":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        actions = corr.get("suggested_actions", [])
                                        act_lines = [f"  >> {a}" for a in actions[:2]]
                                        act_str = ("\n" + "\n".join(act_lines)) if act_lines else ""
                                        corr_lines.append(
                                            f"- [{severity}] EXPERT TEST ({pattern}): {desc}{act_str}")

                                    elif vuln_type == "zeroday_potential":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        vectors = corr.get("test_vectors", [])
                                        vec_lines = [f"  >> {v}" for v in vectors[:2]]
                                        vec_str = ("\n" + "\n".join(vec_lines)) if vec_lines else ""
                                        corr_lines.append(
                                            f"- [{severity}] ZERO-DAY ({pattern}): {desc}{vec_str}"
                                        )

                                    elif vuln_type == "business_logic":
                                        pattern = corr.get("pattern", "?")
                                        desc = corr.get("description", "?")
                                        actions = corr.get("suggested_actions", [])
                                        act_lines = [f"  >> {a}" for a in actions[:2]]
                                        act_str = ("\n" + "\n".join(act_lines)) if act_lines else ""
                                        corr_lines.append(
                                            f"- [{severity}] BUSINESS LOGIC ({pattern}): {desc}{act_str}"
                                        )

                                    elif vuln_type == "attack_chain":
                                        name = corr.get("name", "?")
                                        steps = corr.get("steps", [])
                                        steps_str = " → ".join(steps)
                                        corr_lines.append(
                                            f"- [{severity}] ATTACK CHAIN DETECTED "
                                            f"({name}): {steps_str}"
                                        )

                                    elif vuln_type == "synthesized_chain":
                                        title = corr.get("title", "?")
                                        confidence = corr.get("confidence", 0.0)
                                        steps = corr.get("steps", [])
                                        steps_str = " → ".join(steps[:5])
                                        corr_lines.append(
                                            f"- [{severity}] SYNTHESIZED CHAIN "
                                            f"(conf={confidence:.0%}) {title}"
                                            + (f": {steps_str}" if steps_str else "")
                                        )

                                    else:
                                        corr_lines.append(
                                            f"- [{severity}] Unknown Correlation: {corr}")

                                correlation_prompt = "\n".join(corr_lines)

                        # VULNERABILITY CHAINING ANALYSIS
                        if len(s.vulnerabilities) >= 2:
                            vuln_titles = [
                                v.get("title", v.get("finding", "?"))
                                for v in s.vulnerabilities[:10]
                            ]
                            vuln_chaining_prompt = (
                                f"\n\n[VULNERABILITY CHAINING ANALYSIS]\n"
                                f"You have {len(s.vulnerabilities)} vulnerabilities. Consider chaining:\n"
                                f"Current vulns: {'; '.join(vuln_titles)}\n"
                                f"Analyze if combining these can lead to greater impact:\n"
                                f"- Can XSS be combined with CSRF for session hijacking?\n"
                                f"- Can IDOR + broken auth lead to account takeover?\n"
                                f"- Can SSRF + cloud metadata = full cloud compromise?\n"
                                f"Document attack chains in output/attack_chains.txt"
                            )

                        # EXPERT TESTING & ZERO-DAY DISCOVERY GUIDANCE
                        if s.urls and len(s.urls) > 5:
                            url_str = " ".join(s.urls).lower()
                            expert_patterns = []

                            if "api" in url_str:
                                expert_patterns.append(
                                    "API endpoints detected - FUZZ all parameters with ffuf"
                                )
                            if any(x in url_str for x in [
                                   "user_id", "order_id", "id="]):
                                expert_patterns.append(
                                    "ID parameters found - TEST IDOR: change IDs 1,2,3,999"
                                )
                            if any(x in url_str for x in [
                                   "search", "query", "q="]):
                                expert_patterns.append(
                                    "Search params found - TEST XSS and SQL injection"
                                )
                            if any(x in url_str for x in [
                                   "price", "amount", "discount"]):
                                expert_patterns.append(
                                    "Price params found - TEST business logic manipulation"
                                )
                            if any(x in url_str for x in [
                                   "upload", "file", "image"]):
                                expert_patterns.append(
                                    "File upload found - TEST webshell upload, polyglots"
                                )

                            if expert_patterns:
                                try:
                                    prompt_path = Path(
                                        __file__).parent.parent / "prompts" / "testing.txt"
                                    with open(prompt_path, "r") as pf:
                                        expert_template = pf.read()
                                    patterns_str = "\n".join(
                                        f"- {p}" for p in expert_patterns)
                                    expert_testing_prompt = "\n\n" + \
                                        expert_template.replace(
                                            "{expert_patterns}", patterns_str)
                                except Exception as _tmpl_err:
                                    logger.debug(
                                        "Could not load testing.txt template: %s — using inline fallback",
                                        _tmpl_err,
                                    )
                                    expert_testing_prompt = "\n\n[EXPERT TESTING] " + ", ".join(
                                        expert_patterns)

                    if correlation_prompt or vuln_chaining_prompt or expert_testing_prompt:
                        self.state.conversation.append(
                            {
                                "role": "system",
                                "content": (
                                    f"[SYSTEM: ANALYSIS — Itr {self.state.iteration}]"
                                    f"{correlation_prompt}"
                                    f"{vuln_chaining_prompt}"
                                    f"{expert_testing_prompt}\n"
                                ),
                            }
                        )

                # --- PERIODIC SESSION CHECKPOINT ---
                # Save session every 5 iterations so a crash never loses more
                # than ~5 iterations of work. Tool-execution saves (line ~2340)
                # already cover normal flow; this is the safety net for the
                # gap between tool executions (thinking, planning iterations).
                if self.state.iteration % 5 == 0 and self._has_scan_work():
                    save_session(self._session)  # type: ignore[arg-type]

                # --- PROGRESSIVE CONTEXT SUMMARIZATION ---
                # Every 20 iterations: compress old tool outputs to 1-line summaries
                # and pin confirmed findings so they survive subsequent truncation.
                if self.state.iteration > 0 and self.state.iteration % 20 == 0:
                    self._compress_old_tool_outputs()
                    pinned = self._build_compressed_findings_summary()
                    if pinned:
                        # Replace any existing pinned context (keep only latest)
                        self.state.conversation = [
                            m for m in self.state.conversation
                            if not m.get("content", "").startswith("[SYSTEM: PINNED CONTEXT")
                        ]
                        self.state.conversation.append({
                            "role": "system",
                            "content": pinned,
                        })

                # --- CONTEXT MANAGEMENT (adaptive interval + progressive truncation) ---
                # Dynamic interval: compress more aggressively as context fills.
                # Use session-level override if set, else fall back to config.
                _cur_ctx_limit = self._adaptive_num_ctx or cfg.ollama_num_ctx
                _cur_num_predict = self._get_iteration_num_predict(
                    cfg, current_phase, _cur_ctx_limit
                )
                # Use effective input limit (subtract output reservation) so the
                # compression interval reacts correctly before Ollama truncates.
                _cur_effective_ctx = max(1024, _cur_ctx_limit - _cur_num_predict)
                _cur_token_ratio = (
                    self.state.token_usage.get("used", 0) / max(_cur_effective_ctx, 1)
                )
                if _cur_token_ratio > 0.60:
                    _ctx_interval = 5   # very frequent when getting full
                elif self.state.iteration > 150:
                    _ctx_interval = 10
                else:
                    _ctx_interval = 15
                if self.state.iteration % _ctx_interval == 0:
                    # Prune stale skills before context compression (recover 10K-30K tokens)
                    # Remove skill messages older than 10 iterations that aren't relevant to current phase
                    if self.state.iteration >= 20:  # Only prune after warm-up period
                        self._prune_stale_skills(max_age_iterations=10)
                    
                    # LLM compression is only safe when we have headroom.
                    # Calling ollama.complete() when context is >65% full risks
                    # OOM inside the compression call itself.
                    if _cur_token_ratio < 0.65:
                        # Use a small, safe context window for the compression
                        # call itself so it never triggers OOM.
                        _compress_ctx = min(8192, _cur_ctx_limit // 4)
                        await self.state.compress_with_llm(
                            self.ollama, keep_recent=30,
                            num_ctx=_compress_ctx, num_predict=1024,
                        )
                    else:
                        logger.info(
                            "Skipping LLM compression (context %.0f%% full) "
                            "— truncate-only to avoid OOM during compress",
                            _cur_token_ratio * 100,
                        )
                    # PIN CRITICAL FINDINGS BEFORE TRUNCATION
                    critical_context = self._build_critical_findings_context()
                    # Progressive max_messages: more aggressive as session
                    # grows to limit KV cache
                    if self.state.iteration < 100:
                        _max_msgs = 150
                    elif self.state.iteration < 200:
                        _max_msgs = 120
                    elif self.state.iteration < 300:
                        _max_msgs = 100
                    else:
                        _max_msgs = 80
                    self.state.truncate_conversation(max_messages=_max_msgs)
                    # Re-inject critical findings after truncation
                    if critical_context:
                        self.state.conversation.append(
                            {"role": "system", "content": critical_context}
                        )

                if self.state.iteration > 1 and self.state.iteration % 10 == 0:
                    # Inject session-aware summary instead of just tool history
                    if self._session and self._session.scan_count > 0:
                        session_summary = session_to_context(self._session)
                        self.state.conversation = [
                            msg
                            for msg in self.state.conversation
                            if not msg.get("content", "").startswith(
                                "[SYSTEM: RECENT EXECUTIONS"
                            )
                            and not msg.get("content", "").startswith(
                                "[SYSTEM: PREVIOUS SESSION"
                            )
                        ]
                        self.state.conversation.append(
                            {"role": "system", "content": session_summary}
                        )
                    elif self.state.tool_history:
                        history_ctx = self._build_recent_history_context(
                            last_n=10)
                        if history_ctx:
                            self.state.conversation = [
                                msg
                                for msg in self.state.conversation
                                if not msg.get("content", "").startswith(
                                    "[SYSTEM: RECENT EXECUTIONS"
                                )
                            ]
                            self.state.conversation.append(
                                {"role": "system", "content": history_ctx}
                            )

                # Periodic Caido reminder: inject if Caido is available but not yet
                # used. After iteration 30, Ollama is deep enough that repeating
                # this hint is no longer useful. Replace any existing reminder to
                # avoid accumulation (dedup by prefix).
                _caido_list_used = self.state.tool_counts.get("caido_list_requests", 0)
                _caido_send_used = self.state.tool_counts.get("caido_send_request", 0)
                _caido_auto_used = self.state.tool_counts.get("caido_automate", 0)
                if (
                    getattr(self, "_caido_available", False)
                    and 0 < self.state.iteration <= 30
                    and self.state.iteration % 5 == 0
                    and _caido_list_used == 0
                    and _caido_send_used == 0
                    and _caido_auto_used == 0
                ):
                    self.state.conversation = [
                        msg for msg in self.state.conversation
                        if not msg.get("content", "").startswith(
                            "[SYSTEM: CAIDO REMINDER"
                        )
                    ]
                    self.state.conversation.append({
                        "role": "system",
                        "content": (
                            "[SYSTEM: CAIDO REMINDER] "
                            "Caido proxy is active and has captured HTTP traffic, "
                            "but you have NOT called caido_list_requests yet. "
                            "Call it NOW with filter=target to retrieve all captured "
                            "requests. Real traffic reveals hidden endpoints, auth tokens, "
                            "injection parameters, and app behavior that scanners miss."
                        ),
                    })

                if self.state.is_approaching_limit() and not self.state.warnings_sent:
                    self.state.warnings_sent = True
                    remaining = self.state.max_iterations - self.state.iteration
                    self.state.conversation.append(
                        {
                            "role": "system",
                            "content": f"[SYSTEM: {remaining} iterations remaining]",
                        }
                    )

                thinking_acc = ""
                content_acc = ""
                tool_calls_acc = []
                in_thinking_tag = False
                _carry = ""

                # Context window — use session-level override if a VRAM crash
                # previously occurred, otherwise use config default.
                adaptive_num_ctx = (
                    self._adaptive_num_ctx
                    if self._adaptive_num_ctx > 0
                    else cfg.ollama_num_ctx
                )
                # Keep token_usage["limit"] in sync with actual context window
                # so monitoring/UI always reflects the real limit.
                self.state.token_usage["limit"] = adaptive_num_ctx

                # ── PROACTIVE CONTEXT MONITORING ────────────────────────────
                # If the conversation is approaching the effective INPUT limit,
                # trim NOW before the next call to prevent Ollama silently
                # truncating the system prompt/task mid-stream.
                #
                # Ollama KV cache = input tokens + output tokens ≤ num_ctx.
                # Effective input space = num_ctx - num_predict.
                # When input > effective limit, Ollama discards the oldest
                # tokens (system prompt first) causing silent scope/context loss
                # and hallucination.
                _ctx_used = self.state.token_usage.get("used", 0)
                if _ctx_used > 0 and adaptive_num_ctx > 0:
                    _iter_num_predict = self._get_iteration_num_predict(
                        cfg, current_phase, adaptive_num_ctx
                    )
                    _effective_input_ctx = max(
                        1024, adaptive_num_ctx - _iter_num_predict
                    )
                    _usage_ratio = _ctx_used / _effective_input_ctx
                    # CTF mode: trim earlier (65%) and more aggressively to
                    # prevent the 103-114% overflow seen in logs.
                    _trim_threshold = 0.65 if self._ctf_mode else 0.80
                    if _usage_ratio >= _trim_threshold:
                        logger.warning(
                            "Proactive context trim: %.0f%% used (%d/%d tokens)",
                            _usage_ratio * 100, _ctx_used, adaptive_num_ctx,
                        )
                        # Build both summaries BEFORE truncation (they read session state)
                        _critical_ctx = self._build_critical_findings_context()
                        _handoff_ctx = self._build_handoff_summary()
                        if self._ctf_mode:
                            # CTF: drop to 10-15 messages — keep recent work only
                            _proactive_trim = 10 if _usage_ratio >= 0.80 else 15
                        else:
                            _proactive_trim = 50 if _usage_ratio < 0.90 else 35
                        self.state.truncate_conversation(
                            max_messages=_proactive_trim)
                        # Inject handoff summary first (orientation), then findings (specifics)
                        # AIRecon pattern: structured summary survives truncation as anchor
                        if _handoff_ctx:
                            self.state.conversation.append(
                                {"role": "system", "content": _handoff_ctx}
                            )
                        if _critical_ctx:
                            self.state.conversation.append(
                                {"role": "system", "content": _critical_ctx}
                            )
                # ────────────────────────────────────────────────────────────

                adaptive_temperature = self._get_iteration_temperature(cfg)
                adaptive_num_predict = self._get_iteration_num_predict(
                    cfg, current_phase, adaptive_num_ctx
                )

                # HARD PRE-CALL GUARD: compress conversation if total chars
                # exceed the token budget (1 token ≈ 3 chars).  This runs
                # every iteration and catches large tool outputs that
                # message-count truncation misses.
                await self._enforce_char_budget(
                    num_ctx=adaptive_num_ctx,
                    num_predict=adaptive_num_predict,
                )

                # --- STREAM RECOVERY LOOP ---
                # Up to 6 attempts total:
                #   VRAM crash  → up to 4 retries with escalating truncation
                #                 (ctx and message budget shrink each time)
                #   Connection refused → 4 retries with longer backoff (10s/30s/60s/120s)
                #   Timeout          → 1 retry (already waited; model may finish faster)
                # Any other error is fatal on first occurrence.
                _last_chunk_data = {}  # Store last chunk to extract token info
                _vram_retries_this_iter = 0  # VRAM retries within this iteration
                for _stream_attempt in range(6):
                    try:
                        _requested_num_keep = self._cfg_int(cfg, "ollama_num_keep", 8192)
                        _safe_num_keep = self._fit_num_keep_to_ctx(
                            _requested_num_keep,
                            adaptive_num_ctx,
                            adaptive_num_predict,
                        )
                        if _safe_num_keep != _requested_num_keep:
                            logger.debug(
                                "Clamped num_keep %d -> %d (ctx=%d, predict=%d)",
                                _requested_num_keep,
                                _safe_num_keep,
                                adaptive_num_ctx,
                                adaptive_num_predict,
                            )
                        async for chunk in self.ollama.chat_stream(
                            messages=self._messages_for_ollama(),
                            tools=self._tools_ollama,
                            options={
                                "num_ctx": adaptive_num_ctx,
                                "temperature": adaptive_temperature,
                                "num_predict": adaptive_num_predict,
                                # Protect system prompt from Ollama KV-cache eviction
                                "num_keep": _safe_num_keep,
                                # Prevent repetition loops in long sessions
                                "repeat_penalty": self._cfg_float(
                                    cfg, "ollama_repeat_penalty", 1.05),
                            },
                            think=self._should_use_thinking(cfg, current_phase),
                        ):
                            if hasattr(chunk, "model_dump"):
                                chunk_data = chunk.model_dump()
                            elif isinstance(chunk, dict):
                                chunk_data = chunk
                            else:
                                chunk_data = dict(chunk)

                            _last_chunk_data = chunk_data  # Keep track of last chunk for token info

                            # Honour stop() mid-stream so the agent exits promptly
                            if self._stop_requested:
                                break

                            message = chunk_data.get("message", {})
                            chunk_thinking = message.get("thinking")
                            chunk_tool_calls = message.get("tool_calls")
                            chunk_content = message.get("content", "")

                            if chunk_thinking:
                                thinking_acc += chunk_thinking
                                yield AgentEvent(
                                    type="thinking", data={"content": chunk_thinking}
                                )

                            if chunk_content:
                                text = _carry + chunk_content
                                _carry = ""
                                _OPEN_TAG = "<think>"
                                _CLOSE_TAG = "</think>"
                                # Buffer partial tag suffix to avoid splitting
                                # mid-tag
                                for partial_len in range(
                                        min(len(text), 8), 0, -1):
                                    suffix = text[-partial_len:]
                                    if _OPEN_TAG.startswith(
                                        suffix
                                    ) or _CLOSE_TAG.startswith(suffix):
                                        _carry = suffix
                                        text = text[:-partial_len]
                                        break

                                while text:
                                    if not in_thinking_tag:
                                        if _OPEN_TAG in text:
                                            idx = text.index(_OPEN_TAG)
                                            before = text[:idx]
                                            text = text[idx + len(_OPEN_TAG):]
                                            if before:
                                                content_acc += before
                                                yield AgentEvent(
                                                    type="text", data={"content": before}
                                                )
                                            in_thinking_tag = True
                                        else:
                                            content_acc += text
                                            yield AgentEvent(
                                                type="text", data={"content": text}
                                            )
                                            text = ""
                                    else:
                                        if _CLOSE_TAG in text:
                                            idx = text.index(_CLOSE_TAG)
                                            think_frag = text[:idx]
                                            text = text[idx + len(_CLOSE_TAG):]
                                            if think_frag:
                                                thinking_acc += think_frag
                                                yield AgentEvent(
                                                    type="thinking",
                                                    data={
                                                        "content": think_frag},
                                                )
                                            in_thinking_tag = False
                                        else:
                                            thinking_acc += text
                                            yield AgentEvent(
                                                type="thinking", data={"content": text}
                                            )
                                            text = ""
                            if chunk_tool_calls:
                                tool_calls_acc.extend(chunk_tool_calls)

                        if _carry:
                            content_acc += _carry
                            yield AgentEvent(type="text", data={"content": _carry})
                            _carry = ""

                        # Extract token usage from last chunk
                        if _last_chunk_data:
                            # Ollama returns eval_count (tokens generated) and prompt_eval_count (tokens in prompt).
                            # model_dump() includes all Optional fields as None even when absent;
                            # use `or 0` to guard against None before any arithmetic.
                            eval_count = _last_chunk_data.get("eval_count") or 0
                            prompt_eval_count = _last_chunk_data.get("prompt_eval_count") or 0
                            self._record_token_usage(
                                prompt_tokens=prompt_eval_count,
                                completion_tokens=eval_count,
                            )
                            logger.debug(
                                "Token usage: prompt=%d, generated=%d, total=%d, cumulative=%d",
                                prompt_eval_count, eval_count,
                                prompt_eval_count + eval_count,
                                self.state.token_usage.get("cumulative", 0),
                            )

                        break  # stream completed — exit retry loop
                    except Exception as stream_err:
                        err_str = str(stream_err)
                        err_lower = err_str.lower()
                        _is_vram_crash = (
                            "invalid character '<'" in err_str
                            or "failed to parse JSON" in err_str
                            or "HTML error page" in err_str
                            or "unexpected end of json" in err_lower
                            or "<!doctype" in err_lower
                            or "<html" in err_lower
                            or "out of memory" in err_lower
                            or "cuda out of memory" in err_lower
                            or "llm runner process no longer alive" in err_lower
                            or "signal: killed" in err_lower
                        )
                        _is_conn_refused = "connection refused" in err_lower
                        _is_timeout = (
                            "timeout" in err_lower or "timed out" in err_lower
                        )

                        if _is_vram_crash and _vram_retries_this_iter < 4:
                            # Multi-level VRAM recovery — each crash reduces
                            # context window and message budget further.
                            # The reduced context persists for ALL future
                            # iterations via self._adaptive_num_ctx.
                            self._vram_crash_count += 1
                            _vram_retries_this_iter += 1
                            if self._vram_crash_count == 1:
                                _new_ctx = cfg.ollama_num_ctx_small
                                _max_msgs = 80
                                _wait_s = 0
                            elif self._vram_crash_count == 2:
                                _new_ctx = max(4096, cfg.ollama_num_ctx_small // 2)
                                _max_msgs = 50
                                _wait_s = 5
                            elif self._vram_crash_count == 3:
                                _new_ctx = max(4096, cfg.ollama_num_ctx_small // 4)
                                _max_msgs = 30
                                _wait_s = 10
                            else:
                                # 4+ crashes: absolute minimum; wait for VRAM
                                # to free (model unload/reload cycle).
                                _new_ctx = 4096
                                _max_msgs = 20
                                _wait_s = 30
                            # Persist reduced context + output cap for all
                            # subsequent iterations to prevent recurrence.
                            self._adaptive_num_ctx = _new_ctx
                            adaptive_num_ctx = _new_ctx
                            # Cap output to 1/4 of context (min 512 tokens)
                            # — generating 32K output inside a 4K context is wasteful
                            self._adaptive_num_predict_cap = max(512, _new_ctx // 4)
                            adaptive_num_predict = self._fit_num_predict_to_ctx(
                                min(adaptive_num_predict, self._adaptive_num_predict_cap),
                                _new_ctx,
                            )
                            self._sync_recovery_state_to_session()
                            logger.warning(
                                "VRAM crash #%d — ctx → %d tokens, msgs → %d",
                                self._vram_crash_count, _new_ctx, _max_msgs,
                            )
                            yield AgentEvent(
                                type="text",
                                data={
                                    "content": (
                                        f"\n[AUTO-RECOVERY #{self._vram_crash_count}] "
                                        "VRAM crash — reducing context to "
                                        f"{_new_ctx} tokens, trimming to "
                                        f"{_max_msgs} messages"
                                        + (f", waiting {_wait_s}s..." if _wait_s else "...")
                                        + "\n"
                                    )
                                },
                            )
                            if _wait_s > 0:
                                await asyncio.sleep(_wait_s)
                            self.state.truncate_conversation(
                                max_messages=_max_msgs)
                            recovery_ctx = self._build_recovery_state_context()
                            if recovery_ctx:
                                self.state.conversation.append(
                                    {"role": "system", "content": recovery_ctx}
                                )
                            # Force tool-call-only recovery on the next iteration.
                            self._recovery_force_tool_calls = max(
                                self._recovery_force_tool_calls, 2
                            )
                            self.state.conversation.append(
                                {
                                    "role": "system",
                                    "content": (
                                        "[SYSTEM: RECOVERY MODE — TOOL CALL ONLY]\n"
                                        "A crash occurred. Your next response MUST be a tool call.\n"
                                        "If unsure, call list_files on output/ or run a safe probe.\n"
                                        "Do not write analysis-only text."
                                    ),
                                }
                            )
                            # Save session immediately after recovery so a
                            # second crash doesn't lose accumulated findings.
                            if self._session:
                                try:
                                    save_session(self._session)
                                except Exception as _se:
                                    logger.warning("Could not save session after VRAM recovery: %s", _se)
                            thinking_acc = ""
                            content_acc = ""
                            tool_calls_acc = []
                            in_thinking_tag = False
                            _carry = ""
                            continue  # retry with reduced context

                        elif _is_conn_refused and _stream_attempt < 4:
                            # Connection refused: Ollama may be restarting after
                            # a crash or network hiccup. For large remote models
                            # (122B) reload can take 30-90s — use longer backoff:
                            # attempt 0→10s, 1→30s, 2→60s, 3→120s (total ~220s).
                            _conn_waits = [10, 30, 60, 120]
                            wait_s = _conn_waits[min(_stream_attempt, len(_conn_waits) - 1)]
                            logger.warning(
                                "Ollama connection refused (attempt %d/4) — "
                                "retrying in %ds",
                                _stream_attempt + 1,
                                wait_s,
                            )
                            yield AgentEvent(
                                type="text",
                                data={
                                    "content": (
                                        f"\n[AUTO-RECOVERY] Ollama unreachable "
                                        f"(attempt {_stream_attempt + 1}/4). "
                                        f"Retrying in {wait_s}s...\n"
                                    )
                                },
                            )
                            await asyncio.sleep(wait_s)
                            thinking_acc = ""
                            content_acc = ""
                            tool_calls_acc = []
                            in_thinking_tag = False
                            _carry = ""
                            self._recovery_force_tool_calls = max(
                                self._recovery_force_tool_calls, 1
                            )
                            continue

                        elif _is_timeout and _stream_attempt < 1:
                            # Single retry on timeout — the model may have been
                            # under heavy load or the response was truncated.
                            logger.warning(
                                "Ollama request timed out — retrying once "
                                "(iteration=%d)",
                                self.state.iteration,
                            )
                            yield AgentEvent(
                                type="text",
                                data={
                                    "content": (
                                        "\n[AUTO-RECOVERY] Ollama timed out. "
                                        "Retrying once...\n"
                                    )
                                },
                            )
                            thinking_acc = ""
                            content_acc = ""
                            tool_calls_acc = []
                            in_thinking_tag = False
                            _carry = ""
                            self._recovery_force_tool_calls = max(
                                self._recovery_force_tool_calls, 1
                            )
                            continue

                        # Fatal: all recovery attempts exhausted.
                        if _is_vram_crash:
                            error_msg = (
                                f"Ollama VRAM exhausted after "
                                f"{self._vram_crash_count} recovery attempts. "
                                "Run `systemctl restart ollama` and set "
                                "`ollama_num_ctx` ≤ 8192 in config."
                            )
                        elif _is_conn_refused:
                            error_msg = (
                                "Cannot connect to Ollama after 4 retries "
                                "(connection refused).\n"
                                "Fix: start Ollama with `ollama serve`."
                            )
                        elif "model not found" in err_lower or "pull" in err_lower:
                            error_msg = (
                                f"Model not found: {cfg.ollama_model}\n"
                                f"Fix: run `ollama pull {cfg.ollama_model}`."
                            )
                        elif "context length" in err_lower or "out of memory" in err_lower:
                            error_msg = "Model ran out of context or memory.\nFix: lower `ollama_num_ctx` in config (e.g. 32768)."
                        elif _is_timeout:
                            error_msg = (
                                "Ollama request timed out twice.\n"
                                "Fix: increase `ollama_timeout` in config or "
                                "reduce `ollama_num_ctx`."
                            )
                        else:
                            error_msg = f"Model connection error: {err_str}"
                        logger.error("Ollama stream error: %s", stream_err)
                        yield AgentEvent(type="error", data={"message": error_msg})
                        yield AgentEvent(type="done", data={})
                        return

                if not content_acc and not tool_calls_acc and not thinking_acc:
                    # Empty response = transient Ollama glitch (network hiccup,
                    # remote server busy, transient OOM). Retry up to 4 times
                    # with increasing wait before giving up.
                    # Previously: only 1 retry → agent stopped on second empty.
                    self._empty_response_retry_count = getattr(
                        self, "_empty_response_retry_count", 0
                    ) + 1
                    if self._empty_response_retry_count <= _MAX_EMPTY_RETRIES:
                        _wait = min(5 * self._empty_response_retry_count, 20)
                        logger.warning(
                            "Empty response from Ollama (iteration=%d, attempt=%d/%d) — "
                            "waiting %ds then retrying",
                            self.state.iteration,
                            self._empty_response_retry_count,
                            _MAX_EMPTY_RETRIES,
                            _wait,
                        )
                        # On attempt 3: compact conversation history to recover
                        # from context-overflow-induced empty responses. Keep
                        # system messages and the most recent exchanges; drop
                        # old tool results that inflate the context.
                        if self._empty_response_retry_count == 3:
                            _sys_msgs = [
                                m for m in self.state.conversation
                                if m.get("role") == "system"
                            ][:5]
                            _recent_msgs = [
                                m for m in self.state.conversation
                                if m.get("role") != "system"
                            ][-20:]
                            _before = len(self.state.conversation)
                            # Repair orphaned tool pairs BEFORE sending to Ollama
                            # (AIRecon pattern: prevent Ollama from receiving orphaned tool results)
                            _repaired = AgentState._repair_tool_pairs(_sys_msgs + _recent_msgs)
                            self.state.conversation = _repaired
                            logger.warning(
                                "Empty response retry 3: compacted conversation "
                                "%d → %d messages (pair-repaired) to reduce context size",
                                _before, len(self.state.conversation),
                            )
                        yield AgentEvent(
                            type="text",
                            data={
                                "content": (
                                    f"\n[AUTO-RECOVERY] Empty response from model "
                                    f"(attempt {self._empty_response_retry_count}/{_MAX_EMPTY_RETRIES}). "
                                    f"Waiting {_wait}s and retrying...\n"
                                )
                            },
                        )
                        await asyncio.sleep(_wait)
                        self._recovery_force_tool_calls = max(
                            self._recovery_force_tool_calls, 1
                        )
                        continue  # re-enter the while loop (new iteration)
                    # All retries exhausted — surface error but preserve session
                    self._empty_response_retry_count = 0
                    if self._session:
                        save_session(self._session)
                    yield AgentEvent(
                        type="error",
                        data={
                            "message": (
                                "Empty response from model after 4 retries. "
                                "Possible causes: (1) Ollama OOM — try restarting Ollama or "
                                "reducing ollama_num_ctx in config; "
                                "(2) Model not loaded — run `ollama run <model>` first; "
                                "(3) Context too large — reduce conversation history. "
                                "Session state has been saved — you can resume."
                            )
                        },
                    )
                    yield AgentEvent(type="done", data={})
                    return
                self._empty_response_retry_count = 0

                # --- RESPONSE QUALITY GATE ---
                combined_response = content_acc + " " + thinking_acc
                # Signals that indicate the model is fabricating results instead of running tools.
                # These are tuned for local LLMs (Ollama/Qwen/Llama) which tend to narrate
                # findings confidently without calling tools.
                hallucination_signals = [
                    "i have found",           # Claims finding without tool output
                    "the scan shows",         # Claims scan result without running scan
                    "the results indicate",   # Claims results without tool evidence
                    "my analysis shows",      # Claims analysis without code_analysis tool
                    "it appears that",        # Speculative claim without evidence
                    "based on my knowledge",  # LLM knowledge, not live tool output
                    "without running",        # Explicitly admits no tool used
                    "i don't have access to", # Model refusing instead of using tools
                    "i will run",             # Fake planning instead of executing
                    "let me run",             # Fake planning instead of executing
                    "let me execute",         # Fake planning instead of executing
                    "i'll run",               # Fake planning instead of executing
                    "i'll execute",           # Fake planning instead of executing
                    "i would run",            # Conditional instead of actual execution
                    "next, i'll",             # Step-by-step planning without execution
                    "i should run",           # Obligation without execution
                ]
                combined_lower = combined_response.lower()
                has_hallucination_risk = any(
                    signal in combined_lower for signal in hallucination_signals
                )

                # Bash/shell code block OR plain-text command = LLM wrote a command
                # instead of calling execute{}.
                # _FAKE_CMD_BLOCK_RE catches  ```bash...```  blocks.
                # _FAKE_PLAIN_CMD_RE catches bare  cd /workspace/...&&  or  curl https://...
                # lines that slip through without any backtick wrapping.
                has_fake_cmd_block = (
                    bool(self._FAKE_CMD_BLOCK_RE.search(content_acc))
                    or bool(self._FAKE_PLAIN_CMD_RE.search(content_acc))
                ) if not tool_calls_acc else False

                is_exploit_phase = self.pipeline and self.pipeline.get_current_phase(
                ) == PipelinePhase.EXPLOIT
                has_vulns = self._session and len(
                    self._session.vulnerabilities) > 0
                is_post_vuln_context = has_vulns and (
                    is_exploit_phase or self.state.iteration > 15)

                # Trigger nudge when:
                # - hallucination signal found, OR fake bash block detected
                # - AND no actual tool calls this iteration
                # - Threshold: iteration 1 in any active session; iteration 2 otherwise.
                #
                # In active recon (active_target set), waiting 2 iterations wastes
                # ~60 seconds on a 122B model. Nudge immediately on first text-only
                # response so the model corrects itself before it settles into a loop.
                _in_active_session = bool(self.state.active_target)
                _nudge_threshold_met = (
                    is_post_vuln_context
                    or (_in_active_session and self._no_tool_iterations >= 1)
                    or self._no_tool_iterations >= 2
                )
                if (has_hallucination_risk or has_fake_cmd_block) and not tool_calls_acc:
                    if has_fake_cmd_block:
                        # Code block hallucination — always inject a strong nudge
                        logger.warning(
                            "Bash code block detected in text response (iteration=%d) — "
                            "LLM wrote a command instead of calling execute{}",
                            self.state.iteration,
                        )
                        self.state.conversation.append({
                            "role": "system",
                            "content": (
                                "[SYSTEM: TOOL CALL REQUIRED — DO NOT WRITE COMMANDS AS TEXT]\n"
                                "You wrote a shell command in a code block instead of calling a tool.\n"
                                "Writing ```bash ... ``` does NOT execute the command.\n"
                                "You MUST call the execute tool to run commands:\n"
                                "  execute({\"command\": \"your_command_here\"})\n"
                                "Call the tool NOW. Do not repeat the code block."
                            ),
                        })
                        content_acc = ""  # discard hallucinated text from history
                    elif is_post_vuln_context:
                        # STRICT MODE: After vulnerability found, tool calls are MANDATORY
                        logger.warning(
                            "Post-vulnerability hallucination detected "
                            "(phase=exploit=%s, vulns=%d, no_tool_iters=%d)",
                            is_exploit_phase,
                            len(self._session.vulnerabilities) if self._session else 0,
                            self._no_tool_iterations,
                        )
                        self.state.conversation.append({
                            "role": "system",
                            "content": (
                                "[SYSTEM: MANDATORY TOOL CALL - EXPLOIT PHASE]\n"
                                "A vulnerability was found. You MUST now prove it works:\n"
                                "1. Use a command execution, browser, or fuzzing tool\n"
                                "2. Show the actual response/output as evidence\n"
                                "3. DO NOT write analysis-only text\n"
                                "TOOL EXECUTION IS MANDATORY. Do not skip this step."
                            ),
                        })
                    elif _nudge_threshold_met:
                        logger.warning(
                            "Hallucination signal detected with no tool call "
                            "(iteration=%d, no_tool_iters=%d)",
                            self.state.iteration,
                            self._no_tool_iterations,
                        )
                        self.state.conversation.append({
                            "role": "system",
                            "content": (
                                "[SYSTEM: HALLUCINATION WARNING]\n"
                                "Your response contains claims without tool execution. "
                                "You have NO data unless a tool actually returned it. "
                                "You MUST call a tool to verify any findings. "
                                "Do NOT fabricate results."
                            ),
                        })

                # Fallback: some models emit tool calls as text inside
                # <tool_call> tags
                if not tool_calls_acc:
                    _registered = {
                        t["function"]["name"] for t in (self._tools_ollama or [])
                    }
                    _search_text = content_acc + "\n" + thinking_acc
                    extracted = self._extract_tool_calls_from_text(
                        _search_text, _registered
                    )
                    if extracted:
                        tool_calls_acc.extend(extracted)
                        content_acc = self._TOOL_CALL_RE.sub(
                            "", content_acc).strip()

                # --- TEXT-ONLY RESPONSE DETECTION (ALL PHASES) ---
                # Discard planning/analysis text and force a tool call.
                # Threshold: 1 iteration in active sessions (active_target set),
                # 2 elsewhere. One wasted iteration on a 122B model costs ~60s —
                # intervene immediately rather than waiting for a second failure.
                _text_only_threshold = 1 if _in_active_session else 2
                if not tool_calls_acc and content_acc.strip() and self._no_tool_iterations >= _text_only_threshold:
                    # Check if response is analysis/planning text (not a final answer)
                    _planning_keywords = [
                        "i will", "i'll", "let me", "next step",
                        "i should", "i need to", "i'm going to",
                        "first, i", "to do this", "i would",
                    ]
                    _analysis_keywords = [
                        "analysis", "shows", "found", "detected",
                        "i have", "based on", "my analysis", "the results",
                        "might", "could be", "appears", "potentially",
                    ]
                    _all_no_tool_keywords = _planning_keywords + _analysis_keywords
                    content_lower = content_acc.lower()
                    is_no_tool_text = any(
                        kw in content_lower for kw in _all_no_tool_keywords
                    )
                    current_phase_name = (
                        self.pipeline.get_current_phase().value
                        if self.pipeline else "UNKNOWN"
                    )
                    if is_no_tool_text:
                        logger.warning(
                            "Text-only response for %d consecutive iterations "
                            "in %s phase — discarding and forcing tool call.",
                            self._no_tool_iterations,
                            current_phase_name,
                        )
                        self.state.conversation.append({
                            "role": "system",
                            "content": (
                                f"[SYSTEM: TEXT-ONLY RESPONSES NOT ALLOWED]\n"
                                f"You have provided {self._no_tool_iterations} consecutive "
                                f"responses without calling any tool.\n"
                                f"Current phase: {current_phase_name}\n"
                                f"You MUST call a tool NOW. Do NOT plan or describe — EXECUTE."
                            ),
                        })
                        # Discard the planning text — do not add to conversation history
                        tool_calls_acc = []
                        content_acc = ""

                _has_task_complete = "[TASK_COMPLETE]" in content_acc
                content_acc = content_acc.replace(
                    "[TASK_COMPLETE]", "").strip()

                # --- OBJECTIVE PATCHING ---
                # Strip <objective_patch> block from content before storing in
                # conversation history (keep history clean), then apply ops.
                if "<objective_patch" in content_acc:
                    _patch_count = self._apply_objective_patch(
                        content_acc, current_phase
                    )
                    content_acc = self._OBJECTIVE_PATCH_RE.sub(
                        "", content_acc
                    ).strip()

                self.state.add_message(
                    "assistant", content_acc, tool_calls_acc, thinking_acc
                )

                # HIGH FIX #2 (MODIFIED): Softer conversation claim validation
                # Only interrupt confident false claims about SPECIFIC vulnerabilities
                if self._session and content_acc:
                    # Check if claim is confident (not hedged)
                    hedge_words = [
                        "might", "could", "possibly", "appears", "suggests",
                        "may", "potentially", "likely", "probable", "seems"
                    ]
                    is_confident = not any(hedge in content_acc.lower() for hedge in hedge_words)
                    
                    # Only validate confident claims (allow hypotheses in hedged language)
                    if is_confident:
                        # Extract SPECIFIC vulnerability claims (require endpoint + vuln type)
                        # Pattern requires: vuln type + "in/at" + endpoint (prevents false positives)
                        vuln_claim_patterns = [
                            r"(sql\s*(injection)?|xss|ssrf|idor|rce|lfi|rfi|xxe|command\s+injection)\s+(in|at|on|found\s+in|detected\s+at)\s+([^\s,.!?]+)",
                        ]
                        for pattern in vuln_claim_patterns:
                            matches = re.findall(pattern, content_acc.lower())
                            for match in matches:
                                # Extract the full claim: vuln_type + endpoint
                                if isinstance(match, tuple) and len(match) >= 4:
                                    vuln_type = match[0].strip()
                                    endpoint = match[3].strip()  # group3=endpoint (group2=preposition)
                                    claim_text = f"{vuln_type} in {endpoint}"
                                else:
                                    continue  # Skip malformed matches
                                
                                # Check if claim matches session.vulnerabilities
                                if claim_text and self._session.vulnerabilities:
                                    has_evidence = any(
                                        vuln_type in " ".join(
                                            [
                                                str(v.get("finding", "")),
                                                str(v.get("title", "")),
                                                str(v.get("evidence", "")),
                                                str(v.get("proof", "")),
                                            ]
                                        ).lower()
                                        and endpoint in " ".join(
                                            [
                                                str(v.get("finding", "")),
                                                str(v.get("title", "")),
                                                str(v.get("evidence", "")),
                                                str(v.get("proof", "")),
                                            ]
                                        ).lower()
                                        for v in self._session.vulnerabilities
                                    )
                                    if not has_evidence:
                                        # Inject gentle correction (only for specific confident false claims)
                                        self.state.conversation.append({
                                            "role": "system",
                                            "content": f"[SYSTEM: UNVERIFIED CLAIM] You claimed '{claim_text}' but no tool output supports this. Consider using hedged language like 'might be' or 'appears to be' if not confirmed, or provide tool evidence."
                                        })

                # --- AUTO-LOAD SKILLS FROM LLM OUTPUT (not just user message) ---
                _llm_output_for_skills = (
                    content_acc + " " + thinking_acc).strip()
                if _llm_output_for_skills:
                    # Pass session.loaded_skills for dedup
                    _session_skills_2 = None
                    if self._session:
                        _session_skills_2 = set(self._session.loaded_skills)
                    _new_skill_ctx, _new_loaded_skills = auto_load_skills_for_message(
                        _llm_output_for_skills,
                        phase=self._get_current_phase().value,
                        session_loaded_skills=_session_skills_2,
                    )

                    if _new_loaded_skills:
                        for s in _new_loaded_skills:
                            _skill_name = Path(str(s)).stem
                            if _skill_name not in self.state.skills_used:
                                self.state.skills_used.append(_skill_name)
                        # Track loaded skills in session for dedup across messages
                        if self._session:
                            for skill_rel in _new_loaded_skills:
                                if skill_rel not in self._session.loaded_skills:
                                    self._session.loaded_skills.append(skill_rel)

                    if _new_skill_ctx:
                        # Avoid injecting the same skill context twice in a
                        # session
                        _skill_key = hash(_new_skill_ctx[:200])
                        if not hasattr(self, "_loaded_skill_hashes"):
                            self._loaded_skill_hashes: set[int] = set()
                        if _skill_key not in self._loaded_skill_hashes:
                            self._loaded_skill_hashes.add(_skill_key)
                            # Tag skill messages with iteration for _prune_stale_skills
                            self.state.conversation.append(
                                {"role": "system", "content": _new_skill_ctx, "iteration": self.state.iteration}
                            )
                            logger.debug(
                                "Auto-loaded skill from LLM output keywords"
                            )

                # --- TRACK PLANNED TOOLS ---
                # Extract tools mentioned in assistant's text response and
                # track them
                if content_acc:
                    known_tools = []
                    _categories = _TOOLS_META.get("categories", {})
                    for cat_group in _categories.values():
                        if isinstance(cat_group, dict):
                            for sublist in cat_group.values():
                                if isinstance(sublist, list):
                                    known_tools.extend(sublist)
                        elif isinstance(cat_group, list):
                            known_tools.extend(cat_group)
                    content_lower = content_acc.lower()
                    for tool in known_tools:

                        if re.search(rf"\b{re.escape(tool)}\b", content_lower):
                            if tool not in self.state.planned_tools:
                                self.state.planned_tools.append(tool)

                if not tool_calls_acc:
                    self._no_tool_iterations += 1
                    if _has_task_complete:
                        logger.info(
                            "Agent emitted [TASK_COMPLETE] — stopping.")
                        # Only save if actual scanning work was done
                        if self._has_scan_work():
                            save_session(self._session)  # type: ignore[arg-type]
                        yield AgentEvent(type="done", data={})
                        return

                    # In active recon sessions, do NOT stop on text-only hallucinations.
                    # Force another iteration so the model must produce real tool calls.
                    _force_tool_mode = bool(self.state.active_target)
                    # Always retry text-only responses when there is an active recon
                    # target — the first text-only response must never be treated as a
                    # "final answer" during live recon.  The extra conditions
                    # (has_fake_cmd_block, _no_tool_iterations >= 2, etc.) were too
                    # narrow: they let the first plain-text LLM response escape the
                    # retry path and halt the agent prematurely.
                    _retry_text_only = _force_tool_mode
                    if _retry_text_only:
                        _max_text_only_retries = max(
                            3,
                            int(getattr(cfg, "agent_missing_tool_retry_limit", 2)) + 1,
                        )
                        # --- REFLECTOR PHASE (iterations 1-2) ---
                        # Targeted XML-structured correction before watchdog.
                        # Uses _no_tool_iterations directly as attempt number
                        # so the counter is always in sync — no separate counter.
                        # Inspired by PentAGI's Reflector agent pattern.
                        _reflector_max = 2
                        if self._no_tool_iterations <= _reflector_max:
                            reflector_msg = self._build_reflector_message(
                                content_acc=content_acc,
                                attempt=self._no_tool_iterations,
                                phase=current_phase,
                            )
                            # Remove previous reflector message to avoid accumulation
                            self.state.conversation = [
                                m for m in self.state.conversation
                                if not m.get("content", "").startswith("<reflector ")
                            ]
                            self.state.conversation.append(
                                {"role": "system", "content": reflector_msg}
                            )
                            logger.info(
                                "Reflector attempt %d (phase=%s)",
                                self._no_tool_iterations,
                                current_phase.value,
                            )
                        # --- WATCHDOG PHASE (iterations 3+) ---
                        elif self._no_tool_iterations >= _max_text_only_retries:
                            watchdog_call = self._build_watchdog_tool_call(
                                content_acc=content_acc,
                                thinking_acc=thinking_acc,
                                phase=current_phase,
                            )
                            if self._watchdog_forced_calls >= 3:
                                # Exhausted all watchdog attempts — abort.
                                msg = (
                                    "Model is stuck in text-only mode and watchdog recovery failed. "
                                    "Stopping to avoid infinite loop. "
                                    "Try restarting the model/session and rerun."
                                )
                                logger.error(
                                    "Text-only loop abort: active_target=%r no_tool_iters=%d forced_calls=%d",
                                    self.state.active_target,
                                    self._no_tool_iterations,
                                    self._watchdog_forced_calls,
                                )
                                if self._has_scan_work():
                                    save_session(self._session)  # type: ignore[arg-type]
                                yield AgentEvent(type="error", data={"message": msg})
                                yield AgentEvent(type="done", data={})
                                return
                            elif watchdog_call:
                                # Watchdog extracted a command — inject it.
                                self._watchdog_forced_calls += 1
                                tool_calls_acc = [watchdog_call]
                                self._no_tool_iterations = 0
                                self.state.conversation.append(
                                    {
                                        "role": "system",
                                        "content": (
                                            "[SYSTEM: WATCHDOG AUTO-EXECUTION]\n"
                                            "You were stuck in text-only mode. "
                                            "A fallback tool call was injected to recover execution continuity. "
                                            "Use real tool output and continue with the next highest-value step."
                                        ),
                                    }
                                )
                                logger.warning(
                                    "Watchdog forced tool_call after no-tool loop "
                                    "(target=%r, phase=%s, forced_calls=%d, tool=%s)",
                                    self.state.active_target,
                                    current_phase.value,
                                    self._watchdog_forced_calls,
                                    watchdog_call.get("function", {}).get("name", ""),
                                )
                            else:
                                # Watchdog returned None — no extractable command.
                                self._watchdog_forced_calls += 1
                                logger.warning(
                                    "Watchdog: no command found — injecting recovery nudge "
                                    "(target=%r, phase=%s, no_tool_iters=%d, forced_calls=%d)",
                                    self.state.active_target,
                                    current_phase.value,
                                    self._no_tool_iterations,
                                    self._watchdog_forced_calls,
                                )
                                self._no_tool_iterations = 0
                                self.state.conversation.append(
                                    {
                                        "role": "system",
                                        "content": (
                                            "[SYSTEM: RECOVERY — TOOL CALL REQUIRED]\n"
                                            "You produced text-only output but no tool was called.\n"
                                            "You MUST respond with a tool_call NOW. Do not write analysis text.\n"
                                            "Review your current objective and call the most appropriate tool."
                                        ),
                                    }
                                )

                        if not tool_calls_acc:
                            self.state.conversation.append(
                                {
                                    "role": "system",
                                    "content": (
                                        "[SYSTEM: RETRY REQUIRED — TOOL CALL MISSING]\n"
                                        "Do NOT continue with text analysis.\n"
                                        "You MUST call at least one real tool now "
                                        "(command execution, browser, fuzzing, or file reading).\n"
                                        "Respond with tool_call only."
                                    ),
                                }
                            )
                            logger.warning(
                                "Retrying iteration due to text-only response in recon mode "
                                "(target=%r, no_tool_iters=%d)",
                                self.state.active_target,
                                self._no_tool_iterations,
                            )
                            self._stagnation_iterations += 1
                            continue

                    # Non-recon text-only response: treat as final assistant answer.
                    if not tool_calls_acc:
                        if self._session:
                            save_session(self._session)
                        yield AgentEvent(type="done", data={})
                        return

                # Deduplicate tool calls (Ollama streaming sometimes emits
                # duplicates per chunk)
                seen_tools = set()
                deduped_tool_calls = []
                for tc in tool_calls_acc:
                    tc_str = json.dumps(tc, sort_keys=True)
                    if tc_str not in seen_tools:
                        seen_tools.add(tc_str)
                        deduped_tool_calls.append(tc)
                tool_calls_acc = deduped_tool_calls

                if tool_calls_acc:
                    self._no_tool_iterations = 0
                    self._recovery_force_tool_calls = 0
                    # Reset watchdog counter on successful tool call: the model
                    # recovered, so the 3-token budget is restored for future
                    # text-only episodes in the same session.
                    self._watchdog_forced_calls = 0

                if not content_acc.strip():
                    tool_names_str = ", ".join(
                        tc["function"]["name"] for tc in tool_calls_acc
                    )
                    yield AgentEvent(
                        type="text", data={"content": f"Executing: {tool_names_str}..."}
                    )

                # --- PARALLEL TOOL EXECUTION ---
                # Classify tools into parallelizable groups
                parallelizable_tools = _TOOLS_META.get(
                    "parallelizable_tools", [])

                # Check if tools can run in parallel (same category, different
                # targets)
                tool_groups: dict[str, list[tuple[int, dict, dict]]] = {}
                sequential_only: list[tuple[int, dict, dict]] = []

                for idx, tc in enumerate(tool_calls_acc):
                    tn = tc["function"]["name"]
                    args = self._normalize_tool_args(
                        tn, tc["function"]["arguments"], user_message
                    )

                    # Yield tool start FIRST so UI spinner shows immediately
                    yield AgentEvent(
                        type="tool_start",
                        data={
                            "tool_id": str(idx),
                            "tool": tn,
                            "arguments": args},
                    )

                    # Check if this is a parallelizable tool
                    is_parallel = False
                    if tn == "execute":
                        cmd = args.get("command", "")
                        cmd_parts = cmd.split()
                        # Guard against empty command or bare "cd" with no arg
                        if cmd_parts:
                            try:
                                cmd_bin = (
                                    cmd_parts[1]
                                    if cmd.startswith("cd ") and len(cmd_parts) > 1
                                    else cmd_parts[0]
                                )
                            except IndexError:
                                cmd_bin = ""
                        else:
                            cmd_bin = ""
                        cmd_bin = cmd_bin.rsplit("/", 1)[-1]
                        if cmd_bin in parallelizable_tools:
                            # Group all parallel tools under a single
                            # 'parallel' category
                            if "parallel" not in tool_groups:
                                tool_groups["parallel"] = []
                            tool_groups["parallel"].append((idx, tc, args))
                            is_parallel = True

                    if not is_parallel:
                        sequential_only.append((idx, tc, args))

                all_results: dict[
                    int, tuple
                ] = {}  # idx -> (tc, tool_name, arguments, valid, ...)

                # --- EXECUTE PARALLEL TOOLS ---
                async def execute_single_tool(
                        idx: int, tc: dict, args: dict) -> tuple:
                    """Execute a single tool and return results."""
                    tn = tc["function"]["name"]

                    # --- ANTI-REPEAT GUARD (Priority 2) ---
                    # Block identical commands before they even reach
                    # validation/execution.
                    is_dup, dup_msg = self._is_duplicate_command(tn, args)
                    if is_dup:
                        logger.info("Anti-repeat guard blocked duplicate: %s", tn)
                        return (
                            idx, tc, tn, args,
                            True,   # treat as "success" so it is included in context
                            0.0,
                            {"success": True, "result": dup_msg},
                            None,
                            True,
                        )

                    valid, arg_err = self._validate_tool_args(tn, args)
                    if not valid:
                        return (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": arg_err},
                            None,
                            False,
                        )

                    if tn == "execute":
                        # save old content for post-run merge
                        self._check_output_dedup(args)

                    if tn == "browser_action":
                        s, d, r, o = await self._execute_local_browser_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "create_vulnerability_report":
                        s, d, r, o = await self._execute_report_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn in ("create_file", "read_file", "list_files"):
                        s, d, r, o = await self._execute_filesystem_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "web_search":
                        s, d, r, o = await self._execute_web_search_tool(args)
                        self.state.missing_tool_count = 0
                    elif any(tn == t["function"]["name"] for t in (self._tools_ollama or [])):
                        s, d, r, o = await self._execute_tool_and_record(tn, args)
                        self.state.missing_tool_count = 0
                    else:
                        self.state.missing_tool_count += 1
                        return (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": f"Unknown tool: {tn}"},
                            None,
                            False,
                        )

                    # Post-run: merge new output with pre-existing file content
                    # (if any)
                    if tn == "execute":
                        self._apply_output_merge(args, s)

                    return (idx, tc, tn, args, True, d, r, o, s)

                # Execute parallel groups concurrently
                for _, group_tasks in tool_groups.items():
                    if len(group_tasks) > 1:
                        # Execute tools in parallel
                        tasks = [
                            asyncio.create_task(
                                execute_single_tool(idx, tc, args))
                            for idx, tc, args in group_tasks
                        ]
                        results = await asyncio.gather(*tasks, return_exceptions=True)
                        for (idx, tc, args), res in zip(group_tasks, results):
                            if isinstance(res, Exception):
                                logger.error("Parallel tool error: %s", res)
                                # Inject synthetic error result so tool_end event
                                # is always emitted — prevents TUI spinner hang.
                                tn = tc["function"]["name"]
                                all_results[idx] = (
                                    idx, tc, tn, args, False, 0.0,
                                    {"success": False, "error": str(res)},
                                    None, False,
                                )
                            else:
                                all_results[res[0]] = res
                    else:
                        # Single tool in group - execute normally
                        idx, tc, args = group_tasks[0]
                        res = await execute_single_tool(idx, tc, args)
                        all_results[idx] = res

                # Execute sequential-only tasks
                for idx, tc, args in sequential_only:
                    # Get the result from already-executed parallel task if
                    # exists
                    if idx in all_results:
                        continue
                    tn = tc["function"]["name"]
                    valid, arg_err = self._validate_tool_args(tn, args)
                    if not valid:
                        all_results[idx] = (
                            idx,
                            tc,
                            tn,
                            args,
                            False,
                            0.0,
                            {"success": False, "error": arg_err},
                            None,
                            False,
                        )
                        continue
                    # Save old output content for post-run merge (never blocks)
                    if tn == "execute":
                        self._check_output_dedup(args)

                    if tn == "browser_action":
                        s, d, r, o = await self._execute_local_browser_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "create_vulnerability_report":
                        s, d, r, o = await self._execute_report_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn in ("create_file", "read_file", "list_files"):
                        s, d, r, o = await self._execute_filesystem_tool(tn, args)
                        self.state.missing_tool_count = 0
                    elif tn == "web_search":
                        s, d, r, o = await self._execute_web_search_tool(args)
                        self.state.missing_tool_count = 0
                    elif any(tn == t["function"]["name"] for t in (self._tools_ollama or [])):
                        out_queue: asyncio.Queue[str] = asyncio.Queue()

                        def _on_chunk(text: str) -> None:
                            out_queue.put_nowait(text)

                        # create task
                        t_task = asyncio.create_task(
                            self._execute_tool_and_record(
                                tn, args, on_output=_on_chunk)
                        )

                        # Wait for task while yielding chunks
                        while not t_task.done():
                            try:
                                chunk = await asyncio.wait_for(
                                    out_queue.get(), timeout=0.1
                                )
                                yield AgentEvent(
                                    type="tool_output",
                                    data={
                                        "tool_id": str(idx), "content": chunk},
                                )
                            except asyncio.TimeoutError:
                                pass

                        # flush remaining
                        while not out_queue.empty():
                            chunk = out_queue.get_nowait()
                            yield AgentEvent(
                                type="tool_output",
                                data={"tool_id": str(idx), "content": chunk},
                            )

                        s, d, r, o = t_task.result()
                        self.state.missing_tool_count = 0
                    else:
                        self.state.missing_tool_count += 1
                        tool_list = ", ".join(
                            t["function"]["name"] for t in (self._tools_ollama or [])
                        )
                        error_msg = (
                            "CRITICAL ERROR: You just submitted an empty tool call (missing 'name'). "
                            f"Registered tools: {tool_list}."
                            if not tn
                            else f"Tool '{tn}' does not exist. "
                            f"Registered tools: {tool_list}. "
                            "Use 'execute' to run any shell command in the sandbox."
                        )
                        s, d, r, o = (
                            False,
                            0.0,
                            {"success": False, "error": error_msg},
                            None,
                        )
                        if (
                            self.state.missing_tool_count
                            >= cfg.agent_missing_tool_retry_limit
                        ):
                            yield AgentEvent(
                                type="error",
                                data={
                                    "message": f"Agent called unknown tool '{tn}' {self.state.missing_tool_count}x. Stopping."
                                },
                            )
                            yield AgentEvent(type="done", data={})
                            return
                    # Post-run: merge new output with pre-existing file content
                    # (if any)
                    if tn == "execute":
                        self._apply_output_merge(args, s)
                    all_results[idx] = (idx, tc, tn, args, True, d, r, o, s)

                # Process all results in order and emit events
                for idx in sorted(all_results.keys()):
                    res = all_results[idx]
                    (
                        _,
                        tc,
                        tool_name,
                        arguments,
                        was_valid,
                        duration,
                        result,
                        output_file,
                        success,
                    ) = res

                    if not was_valid:
                        arg_error = result.get(
                            "error", "Unknown validation error")
                        yield AgentEvent(
                            type="tool_end",
                            data={
                                "tool_id": str(idx),
                                "tool": tool_name,
                                "success": False,
                                "duration": 0.0,
                                "result_preview": f"VALIDATION ERROR: {arg_error}",
                                "output_file": None,
                                "tool_counts": self.state.tool_counts,
                                "token_usage": dict(self.state.token_usage),
                                "skills_used": list(self.state.skills_used),
                                "caido": {
                                    "active": (
                                        self.state.tool_counts.get("caido_send_request", 0)
                                        + self.state.tool_counts.get("caido_automate", 0)
                                    ) > 0,
                                    "findings_count": (
                                        self.state.tool_counts.get("caido_send_request", 0)
                                        + self.state.tool_counts.get("caido_automate", 0)
                                    ),
                                },
                            },
                        )
                        self._consecutive_failures += 1
                        self._append_tool_result(
                            tool_name,
                            f"ARGUMENT VALIDATION FAILED: {arg_error}\nFix the arguments and retry.",
                            False,
                            tc.get("id"),
                        )
                        continue

                    yield AgentEvent(
                        type="tool_end",
                        data={
                            "tool_id": str(idx),
                            "tool": tool_name,
                            "success": success,
                            "duration": round(duration, 2),
                            "result_preview": self._truncate_result(result),
                            "output_file": output_file,
                            "tool_counts": self.state.tool_counts,
                            "token_usage": dict(self.state.token_usage),
                            "skills_used": list(self.state.skills_used),
                            "caido": {
                                "active": (
                                    self.state.tool_counts.get("caido_send_request", 0)
                                    + self.state.tool_counts.get("caido_automate", 0)
                                ) > 0,
                                "findings_count": (
                                    self.state.tool_counts.get("caido_send_request", 0)
                                    + self.state.tool_counts.get("caido_automate", 0)
                                ),
                            },
                        },
                    )
                    self._track_tool_usage(tool_name, arguments)

                    if success:
                        self._consecutive_failures = 0
                        self.state.missing_tool_count = 0  # reset on any successful tool
                    else:
                        self._consecutive_failures += 1

                    raw_command = (
                        arguments.get("command", "")
                        if tool_name == "execute"
                        else tool_name
                    )
                    content_str = self._smart_format_tool_result(
                        tool_name, result, success, raw_command
                    )

                    # --- PHASE TOOL FIT CHECK (soft enforcement) ---
                    if self.pipeline:  # type: ignore[attr-defined]
                        phase_warn = self.pipeline.check_tool_phase_fit(
                            tool_name)  # type: ignore[attr-defined]
                        if phase_warn:
                            content_str = phase_warn + "\n\n" + content_str
                    phase_gate_note = self._build_phase_gate_note(
                        tool_name, success)
                    if phase_gate_note:
                        content_str = phase_gate_note + "\n\n" + content_str

                    # --- PHASE 1 ARTIFACT ENFORCEMENT ---
                    if success and tool_name in (
                            "web_search", "browser_action"):
                        content_str += (
                            "\n\n[SYSTEM: MANDATORY FILE SAVE]\n"
                            f"You just executed `{tool_name}` successfully. "
                            "You are STRICTLY FORBIDDEN from keeping these results only in memory. "
                            "You MUST immediately use the `create_file` tool to save these findings "
                            "(URLs, text content, view_source, or console_logs) into the `output/` directory "
                            "(e.g., `output/dork_results.txt` or `output/source.txt`). "
                            "Do NOT proceed until this data is saved to disk!"
                        )

                    # Update session with parsed tool output
                    # Include browser_action, quick_fuzz, code_analysis so
                    # their [SEVERITY]-tagged stdout lines populate session.vulnerabilities.
                    _SESSION_UPDATE_TOOLS = (
                        "execute", "browser_action", "quick_fuzz", "code_analysis"
                    )
                    if success and tool_name in _SESSION_UPDATE_TOOLS and self._session:
                        stdout = (
                            result.get(
                                "stdout", "") or result.get(
                                "result", "") or ""
                        )
                        if isinstance(stdout, str) and stdout.strip():
                            _techs_before = dict(self._session.technologies)
                            _phase_for_parse = self._get_current_phase().value
                            parsed_out = parse_tool_output(
                                raw_command, stdout, phase=_phase_for_parse
                            )
                            if parsed_out and parsed_out.total_count > 0:
                                update_from_parsed_output(
                                    self._session, parsed_out, raw_command
                                )
                                save_session(self._session)
                            # Inject tech-specific skills when new technologies
                            # are fingerprinted by this tool execution.
                            # Fires once per tech: deduped by _loaded_tech_skill_paths.
                            _new_techs = {
                                k: v for k, v in self._session.technologies.items()
                                if k not in _techs_before
                            }
                            if _new_techs:
                                _tech_skill_ctx, _tech_names = auto_load_skills_for_technologies(
                                    _new_techs,
                                    already_loaded=self._loaded_tech_skill_paths,
                                )
                                if _tech_skill_ctx:
                                    self.state.conversation.append(
                                        {"role": "system", "content": _tech_skill_ctx}
                                    )
                                    for _sn in _tech_names:
                                        if _sn not in self.state.skills_used:
                                            self.state.skills_used.append(_sn)
                                    logger.info(
                                        "Tech-skill auto-injected for new techs: %s → skills: %s",
                                        list(_new_techs.keys()),
                                        _tech_names,
                                    )

                    phase_after_tool = self._get_current_phase()
                    meaningful_before = sum(
                        1
                        for e in self.state.evidence_log
                        if float(e.get("confidence", 0.0)) >= _MEANINGFUL_EVIDENCE_THRESHOLD
                    )
                    self._record_evidence_from_result(
                        phase=phase_after_tool.value,
                        tool_name=tool_name,
                        arguments=arguments,
                        result=result,
                        success=success,
                        output_file=output_file,
                    )
                    self._update_objectives_from_tool(
                        phase_after_tool,
                        tool_name,
                        arguments,
                        success,
                        result,
                        output_file,
                    )
                    self._update_objectives_from_session(phase_after_tool)
                    meaningful_after = sum(
                        1
                        for e in self.state.evidence_log
                        if float(e.get("confidence", 0.0)) >= _MEANINGFUL_EVIDENCE_THRESHOLD
                    )
                    self.state.record_tool_outcome(
                        phase_after_tool.value,
                        tool_name,
                        success=bool(success),
                        meaningful_evidence_delta=max(0, meaningful_after - meaningful_before),
                    )

                    # --- EXPLOIT CHAIN ADVANCEMENT ---
                    # When a tool call succeeds in EXPLOIT phase, check if it
                    # matches any active chain's current step tool_hint.
                    # If so, advance that chain to the next step.
                    if (
                        success
                        and phase_after_tool.value == "EXPLOIT"
                        and self.state.exploit_chains
                    ):
                        try:
                            for _cd in self.state.exploit_chains:
                                if _cd.get("status") not in ("planning", "active"):
                                    continue
                                _cs_idx = int(_cd.get("current_step_index", 0))
                                _steps = _cd.get("steps", [])
                                if _cs_idx >= len(_steps):
                                    continue
                                _cur_step = _steps[_cs_idx]
                                _hint = str(_cur_step.get("tool_hint", "")).lower()
                                # For 'execute', match the binary name extracted from
                                # the command args — since all shell commands share the
                                # same tool_name="execute", matching tool_name alone
                                # would never advance shell-based chain steps.
                                _match_token = tool_name.lower()
                                if _match_token == "execute" and isinstance(arguments, dict):
                                    _raw_cmd = str(arguments.get("command", "")).strip()
                                    _stripped = re.sub(r"^cd\s+\S+\s*&&\s*", "", _raw_cmd).strip()
                                    _binary = _stripped.split()[0].lower() if _stripped else ""
                                    _shell_builtins = {"cd", "echo", "export", "source", ".", "for", "while", "if"}
                                    if _binary and _binary not in _shell_builtins:
                                        _match_token = _binary
                                if _hint and (_match_token in _hint or tool_name.lower() in _hint):
                                    # Advance the serialised chain dict directly
                                    _cur_step["status"] = "done"
                                    _next_idx = _cs_idx + 1
                                    _chain_name = _cd.get("name", "?")
                                    _vuln_basis = str(_cd.get("vuln_basis", "")).lower().strip()
                                    if _next_idx >= len(_steps):
                                        _cd["status"] = "completed"
                                        _cd["current_step_index"] = _next_idx
                                        logger.info(
                                            "Exploit chain '%s' COMPLETED after %d steps",
                                            _chain_name, len(_steps),
                                        )
                                        # Mark linked hypothesis confirmed
                                        if _vuln_basis and self.state.hypothesis_queue:
                                            _vb_words = {
                                                w for w in _vuln_basis.split() if len(w) >= 4
                                            }
                                            for _hyp in self.state.hypothesis_queue:
                                                if _hyp.get("status") not in ("pending", "testing"):
                                                    continue
                                                _hwords = set(
                                                    str(_hyp.get("claim", "")).lower().split()
                                                )
                                                if _vb_words & _hwords:
                                                    self.state.update_hypothesis(
                                                        str(_hyp.get("id", "")),
                                                        "confirmed",
                                                        f"Exploit chain '{_chain_name}' completed all steps",
                                                    )
                                                    break
                                    else:
                                        _cd["current_step_index"] = _next_idx
                                        _cd["status"] = "active"
                                        _steps[_next_idx]["status"] = "in_progress"
                                        logger.info(
                                            "Exploit chain '%s' advanced to step %d/%d: %s",
                                            _chain_name,
                                            _next_idx + 1,
                                            len(_steps),
                                            _steps[_next_idx].get("description", "")[:60],
                                        )
                                        # Mark linked hypothesis as actively testing
                                        if _vuln_basis and self.state.hypothesis_queue:
                                            _vb_words = {
                                                w for w in _vuln_basis.split() if len(w) >= 4
                                            }
                                            for _hyp in self.state.hypothesis_queue:
                                                if _hyp.get("status") != "pending":
                                                    continue
                                                _hwords = set(
                                                    str(_hyp.get("claim", "")).lower().split()
                                                )
                                                if _vb_words & _hwords:
                                                    self.state.update_hypothesis(
                                                        str(_hyp.get("id", "")),
                                                        "testing",
                                                        f"Exploit chain '{_chain_name}' in progress (step {_next_idx + 1}/{len(_steps)})",
                                                    )
                                                    break
                                    break  # Advance one chain at a time
                        except Exception as _chain_adv_e:
                            logger.debug("Chain advancement error: %s", _chain_adv_e)

                    # Track per-phase tool usage and inject soft budget warning
                    self.state.record_tool_use(phase_after_tool.value, tool_name)
                    budget_note = self._check_tool_budget(
                        tool_name, phase_after_tool.value)
                    if budget_note:
                        content_str = budget_note + "\n\n" + content_str

                    # WAF Detection Hook: run on http_observe and execute results.
                    # Detects WAF signatures in response headers/body, stores
                    # profile in session.waf_profiles, injects bypass context.
                    if (
                        success
                        and tool_name in ("http_observe", "execute")
                        and self._session
                    ):
                        _waf_headers: dict[str, str] = result.get("headers", {}) or {}
                        _waf_body: str = str(result.get("body_excerpt") or result.get("stdout") or "")[:3000]
                        _waf_status: int = int(result.get("status_code") or 0)
                        if _waf_headers or _waf_body:
                            try:
                                _waf_url = arguments.get("url") or arguments.get("command", "")
                                try:
                                    _waf_host = urlparse(str(_waf_url)).netloc or str(_waf_url)
                                except Exception:
                                    _waf_host = str(_waf_url)[:50]
                                if not _waf_host or " " in _waf_host:
                                    _url_match = re.search(r"https?://[^\s\"']+", str(_waf_url))
                                    if _url_match:
                                        _waf_host = urlparse(_url_match.group(0)).netloc
                                _waf_host = str(_waf_host).strip()[:120]
                                _waf_profile = detect_waf_from_response(
                                    host=_waf_host,
                                    status_code=_waf_status,
                                    headers=_waf_headers,
                                    body_excerpt=_waf_body,
                                    iteration=self.state.iteration,
                                )
                                _existing = self._session.waf_profiles.get(_waf_host)
                                _merged = merge_waf_profiles(
                                    _existing,
                                    _waf_profile,
                                    host=_waf_host,
                                    status_code=_waf_status,
                                    iteration=self.state.iteration,
                                )
                                if _merged:
                                    _old_stats = {}
                                    if isinstance(_existing, dict):
                                        _old_stats = _existing.get("strategy_stats", {}) or {}
                                    # Track strategy effectiveness heuristically from command patterns.
                                    # This gives per-host memory for ranking future bypass attempts.
                                    if tool_name == "execute" and isinstance(arguments, dict):
                                        _cmd_lower = str(arguments.get("command", "")).lower()
                                        _prior_strategies = []
                                        if isinstance(_existing, dict):
                                            _prior_strategies = list(_existing.get("bypass_strategies", []))
                                        _matched_strategy = ""
                                        for _st in _prior_strategies:
                                            _st_l = str(_st).lower()
                                            if "header" in _st_l and any(h in _cmd_lower for h in ("x-forwarded-for", "user-agent", "-h ")):
                                                _matched_strategy = str(_st)
                                                break
                                            if "encoding" in _st_l and ("%25" in _cmd_lower or "%2f" in _cmd_lower or "%27" in _cmd_lower):
                                                _matched_strategy = str(_st)
                                                break
                                            if "case variation" in _st_l and any(k in _cmd_lower for k in ("union", "select", "script")):
                                                _matched_strategy = str(_st)
                                                break
                                            if "verb" in _st_l and any(m in _cmd_lower for m in ("-x post", "-x put", "-x patch", "-x delete")):
                                                _matched_strategy = str(_st)
                                                break
                                        if _matched_strategy:
                                            _stat = _old_stats.setdefault(
                                                _matched_strategy,
                                                {"attempts": 0, "successes": 0},
                                            )
                                            _stat["attempts"] = int(_stat.get("attempts", 0)) + 1
                                            if _waf_status and _waf_status not in (403, 406, 412, 429, 501, 999):
                                                _stat["successes"] = int(_stat.get("successes", 0)) + 1
                                    _ranked = rank_bypass_strategies(_merged, _old_stats)[:8]
                                    _merged.bypass_strategies = _ranked
                                    _history: list[dict[str, Any]] = []
                                    if isinstance(_existing, dict) and isinstance(_existing.get("history"), list):
                                        _history = list(_existing["history"])
                                    _history.append({
                                        "iteration": self.state.iteration,
                                        "status_code": _waf_status,
                                        "tool": tool_name,
                                        "confidence": round(_merged.confidence, 3),
                                        "waf_name": _merged.waf_name,
                                    })
                                    self._session.waf_profiles[_waf_host] = {
                                        "host": _waf_host,
                                        "waf_name": _merged.waf_name,
                                        "confidence": _merged.confidence,
                                        "evidence": _merged.evidence,
                                        "detected_at": self.state.iteration,
                                        "bypass_strategies": _ranked,
                                        "strategy_stats": _old_stats,
                                        "history": _history[-15:],
                                    }
                                    _waf_ctx = build_waf_bypass_context(_merged)
                                    if _waf_ctx:
                                        # Replace any existing WAF bypass context for this host
                                        self.state.conversation = [
                                            m for m in self.state.conversation
                                            if not m.get("content", "").startswith(
                                                f'<waf_bypass host="{_waf_host}"'
                                            )
                                        ]
                                        self.state.conversation.append({
                                            "role": "system",
                                            "content": _waf_ctx,
                                        })
                                        logger.info(
                                            "WAF detected on %s: %s (conf=%.0f%%)",
                                            _waf_host, _merged.waf_name,
                                            _merged.confidence * 100,
                                        )
                            except Exception as _waf_e:
                                logger.debug("WAF detection error: %s", _waf_e)

                    if not success and self._consecutive_failures >= 3:
                        alt_suggestion = self._suggest_alternative_tool(
                            tool_name, raw_command
                        )
                        content_str += (
                            f"\n\n[SYSTEM: {self._consecutive_failures} CONSECUTIVE FAILURES DETECTED] "
                            "MANDATORY: Stop using the current approach. "
                            "Switch to a completely different tool or strategy. "
                            + (
                                f"SUGGESTED ALTERNATIVES: {alt_suggestion}\n"
                                if alt_suggestion
                                else ""
                            )
                            + "If all options are exhausted, document what was tried and emit [TASK_COMPLETE]."
                        )

                    if success and self.state.tool_counts["total"] >= 1:
                        # --- PLANNED TOOLS CHECK ---
                        if self.state.planned_tools:
                            # Get tools that have been executed
                            executed_tools = set()
                            for hist in self.state.tool_history:
                                executed_tools.add(hist.tool_name)

                            # Find unexecuted planned tools
                            unexecuted = [
                                t
                                for t in self.state.planned_tools
                                if t not in executed_tools and t != "execute"
                            ]

                            if unexecuted:
                                content_str += (
                                    f"\n\n[SYSTEM: PLANNED TOOLS NOT EXECUTED!]\n"
                                    "You PLANNED to use these tools but haven't executed them: "
                                    f"{', '.join(unexecuted)}\n"
                                    "You MUST call these tools now before moving to the next phase!"
                                )

                        content_str += (
                            "\n\n[SYSTEM: SELF-CHECK] MANDATORY — Answer these BEFORE continuing:\n"
                            "1. Does this tool generate NEW output not already in output/ directory? (Check first!)\n"
                            "2. If output file exists: is the existing data sufficient, or do you need fresh data?\n"
                            "3. Does this advance toward exploitation, or are you just repeating recon?\n"
                            "4. Have you already run this exact command in this session? (Check tool_history)\n"
                            "If answer to Q1=NO or Q2=sufficient or Q3=recon or Q4=YES: "
                            "SKIP redundant execution, move to next phase or emit [TASK_COMPLETE]."
                        )

                    self._record_tested_endpoint(tool_name, arguments)
                    self._append_tool_result(
                        tool_name, content_str, success, tc.get("id")
                    )
                    # Count per-tool (not per-iteration) for mentor throttling.
                    self._mentor_tool_call_count += 1

                self._refresh_exploration_state()

                # --- MENTOR SUPERVISION ---
                # Inject a post-tool analysis after high-value findings
                # (ANALYSIS/EXPLOIT phase only, throttled to every 3 tool calls
                # OR on any HIGH/CRITICAL severity finding).
                # Guard: only fires when tools actually ran this iteration.
                # Inspired by PentAGI's Mentor Supervision system.
                _mentor_phases = {"ANALYSIS", "EXPLOIT"}
                _in_mentor_phase = current_phase.value.upper() in _mentor_phases
                if all_results and _in_mentor_phase and self.state.evidence_log:
                    # Use last tool name from the processed batch (always defined).
                    _mentor_tool_name = all_results[max(all_results.keys())][2]
                    _last_ev = self.state.evidence_log[-1]
                    _last_sev = int(_last_ev.get("severity", 1))
                    _trigger_mentor = (
                        _last_sev >= 4  # any HIGH/CRITICAL finding
                        or self._mentor_tool_call_count % 3 == 0
                    )
                    if _trigger_mentor:
                        mentor_msg = self._build_mentor_analysis(
                            current_phase=current_phase,
                            tool_name=_mentor_tool_name,
                            evidence_added=True,
                        )
                        # Replace previous mentor message to avoid accumulation
                        self.state.conversation = [
                            m for m in self.state.conversation
                            if not m.get("content", "").startswith("<mentor_analysis")
                        ]
                        self.state.conversation.append(
                            {"role": "system", "content": mentor_msg}
                        )

                # Persist session state incrementally after every tool
                # execution
                if self._session:
                    save_session(self._session)

                if _has_task_complete:
                    logger.info(
                        "Agent emitted [TASK_COMPLETE] after tools — stopping.")
                    yield AgentEvent(type="done", data={})
                    return

            yield AgentEvent(
                type="error", data={"message": "Max tool iterations reached."}
            )
            yield AgentEvent(type="done", data={})

        except Exception as e:
            logger.exception("Fatal error in agent loop")
            yield AgentEvent(
                type="error", data={"message": f"Fatal Agent Error: {str(e)}"}
            )
            yield AgentEvent(type="done", data={})

    # URL-extracting regex for _record_tested_endpoint
    _URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)

    def _record_tested_endpoint(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> None:
        """Extract tested URL from tool arguments and persist it to session.

        Supports: execute (curl/wget/sqlmap/ffuf/nikto/etc), browser_action
        (goto/new_tab), quick_fuzz, advanced_fuzz, deep_fuzz.
        Silently ignores tools that don't target URLs.
        """
        if not self._session:
            return
        url: str = ""
        method: str = "GET"

        if tool_name == "execute":
            cmd = arguments.get("command", "")
            # Extract first URL from command string
            m = self._URL_RE.search(cmd)
            if m:
                url = m.group(0).rstrip("'\"\\;,")
            # Detect HTTP method from curl -X / --request flags
            _method_m = re.search(
                r"(?:-X|--request)\s+([A-Z]+)", cmd, re.IGNORECASE)
            if _method_m:
                method = _method_m.group(1).upper()
            # POST implied by -d / --data flags
            elif re.search(r"\s(?:-d|--data|--data-raw)\s", cmd):
                method = "POST"

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action in ("goto", "new_tab"):
                url = arguments.get("url", "")

        elif tool_name in ("quick_fuzz", "advanced_fuzz", "deep_fuzz",
                           "schemathesis_fuzz"):
            url = arguments.get("url", arguments.get("target", ""))

        if url:
            record_tested_endpoint(self._session, url, method)

    def get_stats(self) -> dict[str, Any]:
        from .owasp import evidence_risk_summary
        _caido_sends = self.state.tool_counts.get("caido_send_request", 0)
        _caido_autos = self.state.tool_counts.get("caido_automate", 0)
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": dict(self.state.tool_counts),
            "token_usage": dict(self.state.token_usage),
            "skills_used": list(self.state.skills_used),
            "caido": {
                "active": (_caido_sends + _caido_autos) > 0,
                "findings_count": _caido_sends + _caido_autos,
            },
            "risk": evidence_risk_summary(self.state.evidence_log),
        }

    def _extract_tool_calls_from_text(
        self, text: str, registered_tools: set[str]
    ) -> list[dict[str, Any]]:
        """Extract tool calls from model text using fault-tolerant JSON parsing.

        Handles:
        - <tool_call>{...}</tool_call> tags
        - Bare JSON objects with 'name' and 'arguments' keys
        - Malformed JSON with trailing commas, comments, unbalanced brackets
        """
        tool_calls: list[dict[str, Any]] = []

        # Step 1: Try <tool_call> tag extraction
        for raw_json in self._TOOL_CALL_RE.findall(text):
            tc = self._parse_tool_call_json(raw_json, registered_tools)
            if tc:
                tool_calls.append(tc)

        if tool_calls:
            return tool_calls

        # Step 2: Try finding bare JSON objects that look like tool calls
        # Match any JSON-like object in the text
        brace_depth = 0
        start_idx = None
        for i, ch in enumerate(text):
            if ch == "{":
                if brace_depth == 0:
                    start_idx = i
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth == 0 and start_idx is not None:
                    candidate = text[start_idx: i + 1]
                    # Only try if it looks like a tool call (has "name" key)
                    if '"name"' in candidate or "'name'" in candidate:
                        tc = self._parse_tool_call_json(
                            candidate, registered_tools)
                        if tc:
                            tool_calls.append(tc)
                    start_idx = None

        return tool_calls

    def _parse_tool_call_json(
        self, raw: str, registered_tools: set[str]
    ) -> dict[str, Any] | None:
        """Try to parse a JSON string as a tool call with auto-repair."""
        parsed = self._try_parse_json(raw)
        if parsed is None:
            return None

        # Extract tool name and arguments from various formats
        tc_name = parsed.get("name") or parsed.get(
            "function", {}).get("name", "")
        tc_args = (
            parsed.get("arguments")
            or parsed.get("parameters")
            or parsed.get("function", {}).get("arguments", {})
            or {}
        )

        if tc_name and tc_name in registered_tools:
            logger.info("[fallback] Extracted tool_call: %s", tc_name)
            return {"function": {"name": tc_name, "arguments": tc_args}}
        return None

    @staticmethod
    def _try_parse_json(raw: str) -> dict | None:
        """Try to parse JSON with auto-repair for common issues."""
        # Attempt 1: direct parse
        try:
            result = json.loads(raw)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 2: strip // and /* */ comments
        # Use possessive-style pattern for /* */ to avoid catastrophic backtracking
        # on unclosed comments in malformed LLM output.
        cleaned = re.sub(r"//[^\n]*", "", raw)
        cleaned = re.sub(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/", "", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 3: fix trailing commas
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Attempt 4: repair truncated JSON by appending closing braces.
        # Naive bracket counting (str.count) is wrong when string values
        # contain literal { or } — e.g. "args": "-T4 {verbose}". Instead,
        # try appending 1–5 closing braces incrementally and stop as soon as
        # json.loads succeeds. This handles truncated LLM output without
        # mis-counting embedded braces.
        for _extra in range(1, 6):
            try:
                result = json.loads(cleaned + "}" * _extra)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        # Attempt 5: replace single quotes with double quotes
        cleaned = cleaned.replace("'", '"')
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        return None

    # Extensions that support line-based merge+sort (text, not
    # binary/structured)
    _MERGEABLE_EXTENSIONS = frozenset(
        {".txt", ".csv", ".list", ".hosts", ".log", ".out"})

    def _get_command_output_file(
            self, arguments: dict[str, Any]) -> tuple[str | None, "Path | None"]:
        """Extract the output file path from a command's -o / --output flags.

        Returns (relative_path_str, full_Path) or (None, None) if not found.
        """
        cmd = arguments.get("command", "")
        if not cmd or not self.state.active_target:
            return None, None
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return None, None

        output_file: str | None = None
        for i, token in enumerate(tokens):
            if token in ("-o", "--output", "-oX", "-oN", "-oG",
                         "-oA", "-oJ") and i + 1 < len(tokens):
                output_file = tokens[i + 1]
                break
            if token.startswith(
                    "-o") and len(token) > 2 and not token.startswith("-oX"):
                output_file = token[2:]
                break

        if not output_file:
            return None, None

        workspace = get_workspace_root() / self.state.active_target
        full_path = (
            workspace / output_file
            if not output_file.startswith("/")
            else Path(output_file)
        )
        return output_file, full_path

    def _check_output_dedup(self, arguments: dict[str, Any]) -> None:
        """If the command's output file already exists, save old content for post-run merge.

        Never blocks — the command always runs. New results are merged+sorted afterwards.
        """
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        if not full_path.exists() or full_path.stat().st_size <= 100:
            return
        # Only pre-save mergeable (line-based) file types
        if full_path.suffix.lower() not in self._MERGEABLE_EXTENSIONS:
            return
        try:
            old_lines = full_path.read_text(errors="ignore").splitlines()
            self._pending_output_merges[str(full_path)] = old_lines
            logger.info("Saved %d existing lines from '%s' for post-run merge", len(old_lines), output_file)
        except Exception as e:
            logger.warning("Could not save old content of '%s' for merge: %s", output_file, e)

    def _apply_output_merge(
            self, arguments: dict[str, Any], success: bool) -> None:
        """After a successful execute, merge old + new output lines, dedup, sort."""
        if not success:
            return
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        old_lines = self._pending_output_merges.pop(str(full_path), None)
        if old_lines is None:
            return  # Nothing pre-saved, nothing to merge
        if not full_path.exists():
            return  # Command produced no output file
        try:
            new_lines = full_path.read_text(errors="ignore").splitlines()
            old_set = {line.strip() for line in old_lines if line.strip()}
            new_set = {line.strip() for line in new_lines if line.strip()}
            added = new_set - old_set
            merged = sorted(old_set | new_set)
            full_path.write_text("\n".join(merged) + "\n", encoding="utf-8")
            logger.info(
                "Merged '%s': %d new entries added, %d total lines (sorted)",
                output_file, len(added), len(merged),
            )
        except Exception as e:
            logger.warning("Failed to merge output file '%s': %s", output_file, e)

    # Tool alternative suggestions for smart retry
    _TOOL_ALTERNATIVES: dict[str, str] = _TOOLS_META.get(
        "tool_alternatives", {})

    def _suggest_alternative_tool(
            self, tool_name: str, command: str = "") -> str:
        """Suggest alternative tools when the current one fails repeatedly."""
        # Try to find the actual binary name from the command
        cmd = command or ""
        cmd_clean = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", cmd).strip()
        binary = cmd_clean.split()[0] if cmd_clean.split() else tool_name
        binary = binary.rsplit("/", 1)[-1]  # strip path
        if binary == "sudo" and len(cmd_clean.split()) > 1:
            binary = cmd_clean.split()[1]

        suggestion = self._TOOL_ALTERNATIVES.get(binary)
        if suggestion:
            return suggestion

        # Generic fallback
        return "Try using a completely different tool. Run 'which <tool>' to verify availability."

    def get_progress(self) -> dict[str, Any]:
        """Return progress data for the /api/progress endpoint."""
        session = self._session
        quality_scores = self._compute_quality_scores()
        progress = {
            "target": self.state.active_target or "none",
            "iteration": self.state.iteration,
            "max_iterations": self.state.max_iterations,
            "tool_counts": self.state.tool_counts,
            "consecutive_failures": self._consecutive_failures,
            "objectives": {
                "total": len(self.state.objective_queue),
                "completed": sum(
                    1
                    for o in self.state.objective_queue
                    if str(o.get("status", "")).lower() == "done"
                ),
            },
            "evidence_count": len(self.state.evidence_log),
            "quality_scores": quality_scores,
            "session": None,
        }
        if session:
            progress["session"] = {
                "subdomains": len(session.subdomains),
                "live_hosts": len(session.live_hosts),
                "open_ports": sum(len(p) for p in session.open_ports.values()),
                "urls": len(session.urls),
                "vulnerabilities": len(session.vulnerabilities),
                "tools_run": session.tools_run,
                "scan_count": session.scan_count,
                "completed_phases": session.completed_phases,
            }
        return progress
