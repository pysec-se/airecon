from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shlex
import warnings

import aiohttp  # noqa: F401
from collections import deque
from pathlib import Path
from typing import Any

from ..config import get_config, get_workspace_root
from ..docker import DockerEngine
from ..ollama import OllamaClient
from ..system import get_system_prompt
from .executors import _ExecutorMixin
from .formatters import _FormatterMixin
from .loop_context import _ContextMixin
from .loop_exploration import _ExplorationMixin
from .loop_inference import _InferenceMixin
from .loop_objectives import _ObjectivesMixin
from .loop_lifecycle import _LifecycleMixin
from .loop_policy import is_simple_target_kickoff
from .loop_process import _ProcessMessageMixin
from .loop_state import _StateMixin
from .loop_supervision import _SupervisionMixin
from .models import AgentState
from .pipeline import PipelineEngine, PipelinePhase
from .session import SessionData, load_session, record_tested_endpoint  # noqa: F401
from .validators import _ValidatorMixin
from .workspace import _WorkspaceMixin


def _estimate_tokens(text: str) -> int:

    if not text:
        return 0
    return len(text) // 4


_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(
        f"tools_meta.json unavailable ({_e}); tool catalog features disabled."
    )
    _TOOLS_META = {}

logger = logging.getLogger("airecon.agent")

__all__ = ["AgentLoop", "get_config", "get_system_prompt"]

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
    _StateMixin,
    _LifecycleMixin,
    _ProcessMessageMixin,
):
    _TOOL_CALL_RE = re.compile(
        r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
        re.DOTALL | re.IGNORECASE,
    )

    _FAKE_CMD_BLOCK_RE = re.compile(
        r"```(?:bash|sh|shell|cmd|terminal|zsh)?\s*\n(.+?)```",
        re.DOTALL | re.IGNORECASE,
    )

    _FAKE_PLAIN_CMD_RE = re.compile(
        r"(?m)^[ \t]*"
        r"(?:"
        r"cd\s+/workspace/\S+\s*&&"
        r"|(?:curl|wget)\s+https?://\S+\s*(?:&&|\||;|\\)"
        r")",
    )

    _DEDUP_EXEMPT_TOOLS = frozenset(
        {
            "create_file",
            "create_vulnerability_report",
            "spawn_agent",
        }
    )

    _DEDUP_EXEMPT_BROWSER_ACTIONS = frozenset(
        {
            "click",
            "type",
            "press_key",
            "scroll_down",
            "scroll_up",
            "wait",
            "get_console_logs",
            "get_network_logs",
            "login_form",
            "handle_totp",
            "save_auth_state",
            "inject_cookies",
            "oauth_authorize",
        }
    )

    _CTF_MAX_ITERATIONS = 150

    def __init__(self, ollama: OllamaClient, engine: DockerEngine) -> None:
        self.ollama = ollama
        self.engine = engine
        self.state = AgentState()
        self._tools_ollama: list[dict[str, Any]] | None = None
        self._last_output_file: str | None = None
        self._executed_tool_counts: dict[tuple[str, str], int] = {}

        self._executed_cmd_hashes: set[str] = set()
        self._executed_cmd_order: deque[str] = deque()
        self._initial_messages: list[dict[str, Any]] = []
        self._stop_requested: bool = False
        self._consecutive_failures: int = 0

        self._no_tool_iterations: int = 0
        self._stagnation_iterations: int = 0
        self._recent_tool_names: list[str] = []
        self._last_evidence_count: int = 0
        self._watchdog_forced_calls: int = 0
        self._empty_response_retry_count: int = 0

        self._prev_phase: PipelinePhase | None = None

        self._mentor_tool_call_count: int = 0

        self._recovery_force_tool_calls: int = 0
        self._session: SessionData | None = None
        self._pending_output_merges: dict[str, list[str]] = {}
        self._blocked_tools: set[str] = set()
        self._session_lock = asyncio.Lock()

        self._override_max_iterations: int | None = None
        self._ctf_mode: bool = False

        self._is_subagent: bool = False
        self.pipeline: PipelineEngine | None = None

        self._loaded_tech_skill_paths: set[str] = set()

        self._loaded_skill_hashes: set[int] = set()

        self._adaptive_num_ctx: int = 0

        self._vram_crash_count: int = 0

        self._adaptive_num_predict_cap: int = 0

        self._token_snapshot_task: asyncio.Task[None] | None = None
        self._token_snapshot_resave_requested: bool = False

        self._compression_summary: str = ""

        self._budget_pressure_level: int = 0

        self._last_token_snapshot_time: float = 0.0

        self._last_user_input_time: float = 0.0
        self._user_input_cooldown: float = 30.0

        self._last_conversation_save_iteration: int = 0
        self._conversation_save_interval: int = 10

        self._last_memory_save_iteration: int = 0
        self._memory_save_interval: int = 5
        self._memory_manager = None

        self._request_times = deque(maxlen=10)
        self._last_request_time = 0.0
        self._last_context_validation = 0
        self._last_saved_cumulative: int = 0

        self._user_input_event: asyncio.Event | None = None
        self._user_input_value: str = ""
        self._user_input_cancelled: bool = False
        self._user_input_request_id: str = ""
        self._user_input_prompt: str = ""
        self._user_input_type: str = "text"

        self._scope_lock_active: bool = False
        self._scope_lock_brief: str = ""
        self._scope_anchor_target: str = ""

        self._memory_health_status: dict[str, Any] = {}
        self._last_memory_health_check_iteration: int = -1
        self._memory_health_interval: int = 10

        self._visited_browser_urls: set[str] = set()
        self._max_browser_visits_per_domain: int = 3

    def _is_simple_target_kickoff(
        self,
        user_message: str,
        extracted_target: str | None,
    ) -> bool:
        return is_simple_target_kickoff(user_message, extracted_target)

    async def stop(self) -> None:
        logger.warning("Stopping Agent Loop...")
        self._stop_requested = True

        if self._session and self._session.target:
            try:
                logger.info(
                    "Saving session data (subdomains: %d, live_hosts: %d, vulns: %d, conversation: %d msgs)...",
                    len(self._session.subdomains),
                    len(self._session.live_hosts),
                    len(self._session.vulnerabilities),
                    len(self._session.conversation)
                    if hasattr(self._session, "conversation")
                    else 0,
                )

                self._sync_token_usage_to_session()
                self._sync_recovery_state_to_session()
                self._sync_conversation_to_session()

                async with self._session_lock:
                    from .session import save_session

                    save_session(self._session)
                logger.info(
                    "Session saved to ~/.airecon/sessions/%s.json",
                    self._session.session_id,
                )

                try:
                    from ..memory import get_memory_manager

                    memory = get_memory_manager()

                    memory.save_session(
                        {
                            "session_id": self._session.session_id,
                            "target": self._session.target,
                            "current_phase": self._session.current_phase,
                            "subdomains": list(self._session.subdomains),
                            "live_hosts": list(self._session.live_hosts),
                            "vulnerabilities": self._session.vulnerabilities,
                            "token_total": self._session.token_total,
                            "model_used": self.ollama.model
                            if hasattr(self, "ollama")
                            else None,
                        }
                    )

                    memory.save_target_intel(
                        {
                            "target": self._session.target,
                            "subdomains": list(self._session.subdomains),
                            "ports": self._session.open_ports,
                            "technologies": self._session.technologies,
                        }
                    )

                    logger.debug("Session saved to memory database")
                except Exception as _mem_err:
                    logger.debug("Memory database save failed: %s", _mem_err)

            except Exception as e:
                logger.error("Failed to save session during stop: %s", e)

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

    def _is_duplicate_browser_url(self, url: str, action: str) -> bool:
        if action not in ("goto", "new_tab"):
            return False

        if not url:
            return False

        try:
            normalized = url.strip().lower()
            normalized = re.sub(r"^https?://", "", normalized)
            normalized = re.sub(r"/+$", "", normalized)
        except Exception:
            return False

        count = sum(
            1 for visited in self._visited_browser_urls if visited == normalized
        )
        if count >= self._max_browser_visits_per_domain:
            return True

        return False

    def _is_duplicate_command(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[bool, str]:
        if tool_name in self._DEDUP_EXEMPT_TOOLS:
            return False, ""

        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in self._DEDUP_EXEMPT_BROWSER_ACTIONS:
                return False, ""

            if action in ("goto", "new_tab"):
                url = args.get("url", "")
                if self._is_duplicate_browser_url(url, action):
                    msg = (
                        f"[BROWSER URL LIMIT] URL '{url[:50]}...' has been visited "
                        f"too many times ({self._max_browser_visits_per_domain}). "
                        "Proceed without browser testing for now and focus on other methods."
                    )
                    return True, msg

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

        try:
            _phase_ctx = self._get_current_phase().value
        except Exception:
            _phase_ctx = "unknown"
        raw = f"{_phase_ctx}:{tool_name}:{canonical}"
        cmd_hash = hashlib.md5(
            raw.encode("utf-8", errors="replace"), usedforsecurity=False
        ).hexdigest()

        if cmd_hash in self._executed_cmd_hashes:
            msg = (
                f"[ANTI-REPEAT] Command '{tool_name}' with identical arguments was already "
                "executed. The result is already in your tool history. "
                "Do NOT repeat it — use the existing result and proceed to the next step."
            )
            return True, msg

        if tool_name == "browser_action":
            action = args.get("action", "")
            if action in ("goto", "new_tab"):
                url = args.get("url", "")
                if url:
                    try:
                        normalized = url.strip().lower()
                        normalized = re.sub(r"^https?://", "", normalized)
                        normalized = re.sub(r"/+$", "", normalized)
                        if len(self._visited_browser_urls) > 500:
                            self._visited_browser_urls = set(
                                list(self._visited_browser_urls)[-200:]
                            )
                        self._visited_browser_urls.add(normalized)
                    except Exception as e:
                        logger.debug(
                            "Expected failure normalizing browser URL for dedup: %s", e
                        )

        self._executed_cmd_hashes.add(cmd_hash)
        self._executed_cmd_order.append(cmd_hash)

        if len(self._executed_cmd_hashes) > 5000:
            before = len(self._executed_cmd_hashes)
            while len(self._executed_cmd_order) > 2500:
                oldest = self._executed_cmd_order.popleft()
                self._executed_cmd_hashes.discard(oldest)
            while len(self._executed_cmd_order) > len(self._executed_cmd_hashes):
                self._executed_cmd_order.popleft()
            after = len(self._executed_cmd_hashes)
            if after != before:
                logger.debug(
                    "_executed_cmd_hashes incrementally pruned: %d → %d entries (kept newest 2500)",
                    before,
                    after,
                )

        return False, ""

    _URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)

    def _record_tested_endpoint(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> None:
        if not self._session:
            return
        url: str = ""
        method: str = "GET"

        if tool_name == "execute":
            cmd = arguments.get("command", "")

            m = self._URL_RE.search(cmd)
            if m:
                url = m.group(0).rstrip("'\"\\;,")

            _method_m = re.search(r"(?:-X|--request)\s+([A-Z]+)", cmd, re.IGNORECASE)
            if _method_m:
                method = _method_m.group(1).upper()

            elif re.search(r"\s(?:-d|--data|--data-raw)\s", cmd):
                method = "POST"

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action in ("goto", "new_tab"):
                url = arguments.get("url", "")

        elif tool_name in (
            "quick_fuzz",
            "advanced_fuzz",
            "deep_fuzz",
            "schemathesis_fuzz",
        ):
            url = arguments.get("url", arguments.get("target", ""))

        if url:
            record_tested_endpoint(self._session, url, method)

    def get_stats(self) -> dict[str, Any]:
        from .owasp import evidence_risk_summary

        _caido_sends = self.state.tool_counts.get("caido_send_request", 0)
        _caido_autos = self.state.tool_counts.get("caido_automate", 0)
        _caido_findings = _caido_sends + _caido_autos
        _caido_available = bool(getattr(self, "_caido_available", False))
        return {
            "message_count": len(self.state.conversation),
            "tool_counts": dict(self.state.tool_counts),
            "token_usage": dict(self.state.token_usage),
            "skills_used": list(self.state.skills_used),
            "caido": {
                "active": _caido_available or _caido_findings > 0,
                "findings_count": _caido_findings,
            },
            "risk": evidence_risk_summary(self.state.evidence_log),
        }

    def _extract_tool_calls_from_text(
        self, text: str, registered_tools: set[str]
    ) -> list[dict[str, Any]]:
        tool_calls: list[dict[str, Any]] = []

        for raw_json in self._TOOL_CALL_RE.findall(text):
            tc = self._parse_tool_call_json(raw_json, registered_tools)
            if tc:
                tool_calls.append(tc)

        if tool_calls:
            return tool_calls

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
                    candidate = text[start_idx : i + 1]

                    if '"name"' in candidate or "'name'" in candidate:
                        tc = self._parse_tool_call_json(candidate, registered_tools)
                        if tc:
                            tool_calls.append(tc)
                    start_idx = None

        return tool_calls

    def _parse_tool_call_json(
        self, raw: str, registered_tools: set[str]
    ) -> dict[str, Any] | None:
        parsed = self._try_parse_json(raw)
        if parsed is None:
            return None

        tc_name = parsed.get("name") or parsed.get("function", {}).get("name", "")
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
        try:
            result = json.loads(raw)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        cleaned = re.sub(r"//[^\n]*", "", raw)
        cleaned = re.sub(r"/\*[^*]*(?:\*(?!/)[^*]*)*\*/", "", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        for _extra in range(1, 6):
            try:
                result = json.loads(cleaned + "}" * _extra)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        cleaned = cleaned.replace("'", '"')
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        return None

    _MERGEABLE_EXTENSIONS = frozenset(
        {".txt", ".csv", ".list", ".hosts", ".log", ".out"}
    )

    def _get_command_output_file(
        self, arguments: dict[str, Any]
    ) -> tuple[str | None, "Path | None"]:
        cmd = arguments.get("command", "")
        if not cmd or not self.state.active_target:
            return None, None
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            return None, None

        output_file: str | None = None
        for i, token in enumerate(tokens):
            if token in (
                "-o",
                "--output",
                "-oX",
                "-oN",
                "-oG",
                "-oA",
                "-oJ",
            ) and i + 1 < len(tokens):
                output_file = tokens[i + 1]
                break
            if (
                token.startswith("-o")
                and len(token) > 2
                and not token.startswith("-oX")
            ):
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
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        if not full_path.exists() or full_path.stat().st_size <= 100:
            return

        if full_path.suffix.lower() not in self._MERGEABLE_EXTENSIONS:
            return
        try:
            old_lines = full_path.read_text(errors="ignore").splitlines()
            self._pending_output_merges[str(full_path)] = old_lines
            logger.info(
                "Saved %d existing lines from '%s' for post-run merge",
                len(old_lines),
                output_file,
            )
        except Exception as e:
            logger.warning(
                "Could not save old content of '%s' for merge: %s", output_file, e
            )

    def _apply_output_merge(self, arguments: dict[str, Any], success: bool) -> None:
        if not success:
            return
        output_file, full_path = self._get_command_output_file(arguments)
        if not output_file or not full_path:
            return
        old_lines = self._pending_output_merges.pop(str(full_path), None)
        if old_lines is None:
            return
        if not full_path.exists():
            return
        try:
            new_lines = full_path.read_text(errors="ignore").splitlines()
            old_set = {line.strip() for line in old_lines if line.strip()}
            new_set = {line.strip() for line in new_lines if line.strip()}
            added = new_set - old_set
            merged = sorted(old_set | new_set)
            full_path.write_text("\n".join(merged) + "\n", encoding="utf-8")
            logger.info(
                "Merged '%s': %d new entries added, %d total lines (sorted)",
                output_file,
                len(added),
                len(merged),
            )
        except Exception as e:
            logger.warning("Failed to merge output file '%s': %s", output_file, e)

    _TOOL_ALTERNATIVES: dict[str, str] = _TOOLS_META.get("tool_alternatives", {})

    def _suggest_alternative_tool(self, tool_name: str, command: str = "") -> str:

        cmd = command or ""
        cmd_clean = re.sub(r"^cd\s+/workspace/[^\s]+\s*&&\s*", "", cmd).strip()
        binary = cmd_clean.split()[0] if cmd_clean.split() else tool_name
        binary = binary.rsplit("/", 1)[-1]
        if binary == "sudo" and len(cmd_clean.split()) > 1:
            binary = cmd_clean.split()[1]

        suggestion = self._TOOL_ALTERNATIVES.get(binary)
        if suggestion:
            return suggestion

        return "Try using a completely different tool. Run 'which <tool>' to verify availability."

    def get_progress(self) -> dict[str, Any]:
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

    def _trim_conversation_to_limit(self) -> None:
        cfg = get_config()
        max_conversation_length = getattr(cfg, "agent_max_conversation_messages", 1000)
        if (
            not max_conversation_length
            or len(self.state.conversation) <= max_conversation_length
        ):
            return

        before_count = len(self.state.conversation)
        important_messages = []
        regular_messages = []
        for msg in self.state.conversation:
            content = msg.get("content", "")
            if msg.get("role") == "system" and (
                "[SYSTEM:" in content
                or "Phase transition" in content
                or "objective" in content.lower()
            ):
                important_messages.append(msg)
            else:
                regular_messages.append(msg)

        max_regular = max(0, max_conversation_length - len(important_messages))
        recent_regular = regular_messages[-max_regular:] if max_regular > 0 else []
        self.state.conversation = important_messages + recent_regular
        logger.info(
            "Proactively trimmed conversation from %d to %d messages",
            before_count,
            len(self.state.conversation),
        )

    def _validate_context_relevance(self):
        if not self.state.conversation:
            return

        current_target = self.state.active_target
        if current_target:
            before_count = len(self.state.conversation)
            filtered_conversation = []
            for msg in self.state.conversation:
                content = msg.get("content", "")
                if (
                    "[SYSTEM: ACTIVE_TARGET=" in content
                    and current_target not in content
                ):
                    continue
                if "previous scan of" in content and current_target not in content:
                    continue
                filtered_conversation.append(msg)

            self.state.conversation = filtered_conversation
            removed_count = before_count - len(filtered_conversation)
            if removed_count > 0:
                logger.info("Removed %d outdated context messages", removed_count)

        self._trim_conversation_to_limit()
