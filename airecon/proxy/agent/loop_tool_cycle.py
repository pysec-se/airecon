from __future__ import annotations

import asyncio
import json
import logging
import warnings
from pathlib import Path
from typing import Any, AsyncIterator

from .models import AgentEvent, AgentState
from .loop_cycle_prelude import _CyclePreludeMixin
from .loop_cycle_llm import _CycleLlmMixin
from .loop_cycle_post import _CyclePostMixin
from .session import save_session

logger = logging.getLogger("airecon.agent")
_MAX_EMPTY_RETRIES = 4

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable ({_e}); tool catalog features disabled.")
    _TOOLS_META = {}


class _ToolCycleMixin(_CyclePreludeMixin, _CycleLlmMixin, _CyclePostMixin):
    async def _run_iteration_loop(self, cfg: Any) -> AsyncIterator[AgentEvent]:
        while self.state.iteration < self.state.max_iterations:
            if self._stop_requested:
                yield AgentEvent(
                    type="error", data={"message": "Agent stopped by user."}
                )
                yield AgentEvent(type="done", data={})
                return

            self.state.increment_iteration()
            current_phase = self._get_current_phase()
            
            await self._run_iteration_housekeeping(cfg, current_phase)

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

            adaptive_num_ctx = (
                self._adaptive_num_ctx
                if self._adaptive_num_ctx > 0
                else cfg.ollama_num_ctx
            )

            if adaptive_num_ctx == -1:

                self.state.token_usage["limit"] = -1
                logger.debug("Context window: unlimited (-1) — using Ollama server default")
            else:

                min_recommended_ctx = 8192
                if adaptive_num_ctx < min_recommended_ctx:
                    logger.warning(f"Context size {adaptive_num_ctx} is below minimum recommended {min_recommended_ctx}, increasing")
                    adaptive_num_ctx = min_recommended_ctx

                self.state.token_usage["limit"] = adaptive_num_ctx

            # Hard token budget check BEFORE LLM call to prevent OOM crash.
            # IMPORTANT: Use current-context usage (`used`), not session-lifetime
            # cumulative totals (`cumulative`). Cumulative tracks accounting, not
            # active prompt pressure.
            _ctx_used = self._recompute_used_tokens_from_conversation()
            _budget_hard_limit = int(adaptive_num_ctx * 0.85)  # 85% safety margin

            if adaptive_num_ctx > 0 and _ctx_used > _budget_hard_limit:
                logger.error(
                    "TOKEN BUDGET EXCEEDED: used=%d/%d (%.0f%%) - "
                    "Hard limit=%d (85%%) - forcing aggressive context reset",
                    _ctx_used,
                    adaptive_num_ctx,
                    (_ctx_used / adaptive_num_ctx) * 100,
                    _budget_hard_limit,
                )
                # Use the reset mechanism with summary injection
                await self._reset_ollama_context()
                # Truncate conversation to minimal safe state
                self.state.conversation = self.state.conversation[-20:]
                # Re-inject critical context
                self.state.conversation.append(
                    {"role": "system", "content": self._build_critical_findings_context()}
                )
                self.state.conversation.append(
                    {"role": "system", "content": self._build_handoff_summary()}
                )
                # Recompute live context pressure after recovery mutation.
                self._recompute_used_tokens_from_conversation()
                # Skip this iteration, resume after recovery
                yield AgentEvent(
                    type="text",
                    data={"content": "[SYSTEM: Context budget exceeded, recovery initiated]"},
                )
                continue  # Skip to next iteration
            
            # Normal context pressure checks
            if _ctx_used > 0 and adaptive_num_ctx > 0:
                _iter_num_predict = self._get_iteration_num_predict(
                    cfg, current_phase, adaptive_num_ctx
                )
                _effective_input_ctx = max(
                    1024, adaptive_num_ctx - _iter_num_predict
                )
                _usage_ratio = _ctx_used / _effective_input_ctx

                _trim_threshold = 0.55 if self._ctf_mode else 0.60

                _hard_cap_ratio = 0.75

                if _usage_ratio >= _hard_cap_ratio:

                    logger.error(
                        "EMERGENCY CONTEXT TRIM: %.0f%% used (%d/%d tokens) — "
                        "Ollama overload imminent, forcing aggressive trim",
                        _usage_ratio * 100, _ctx_used, adaptive_num_ctx,
                    )

                    _sys_msgs_e = [
                        m for m in self.state.conversation
                        if m.get("role") == "system"
                    ]
                    _non_sys_e = [
                        m for m in self.state.conversation
                        if m.get("role") != "system"
                    ]
                    _emergency_trim = max(int(len(_non_sys_e) * 0.40), 6)
                    _prev_total = len(self.state.conversation)
                    self.state.conversation = _sys_msgs_e + _non_sys_e[-_emergency_trim:]

                    _msg_ratio = len(self.state.conversation) / _prev_total
                    self.state.token_usage["used"] = int(_ctx_used * _msg_ratio)

                    logger.warning(
                        "Emergency trim: %d → %d msgs (sys=%d kept, "
                        "non-sys %d → %d), est tokens %.0f%% → %.0f%%",
                        _prev_total, len(self.state.conversation),
                        len(_sys_msgs_e), len(_non_sys_e), _emergency_trim,
                        _usage_ratio * 100,
                        _usage_ratio * _msg_ratio * 100,
                    )
                elif _usage_ratio >= _trim_threshold:

                    if _usage_ratio >= 0.60:
                        logger.warning(
                            "CONTEXT PRESSURE EARLY WARNING: %.0f%% used (%d/%d tokens) — "
                            "Agent should start consolidating findings",
                            _usage_ratio * 100, _ctx_used, adaptive_num_ctx,
                        )

                    logger.warning(
                        "Proactive context trim: %.0f%% used (%d/%d tokens)",
                        _usage_ratio * 100, _ctx_used, adaptive_num_ctx,
                    )

                    _critical_ctx = self._build_critical_findings_context()
                    _handoff_ctx = self._build_handoff_summary()
                    if self._ctf_mode:

                        _proactive_trim = 15 if _usage_ratio >= 0.80 else 20
                    else:
                        # More aggressive trimming for non-CTF mode
                        if _usage_ratio >= 0.70:
                            _proactive_trim = 40
                        elif _usage_ratio >= 0.65:
                            _proactive_trim = 60
                        else:
                            _proactive_trim = 80

                    self.state.truncate_conversation(
                        max_messages=_proactive_trim)

                    if _handoff_ctx:
                        self.state.conversation.append(
                            {"role": "system", "content": _handoff_ctx}
                        )
                    if _critical_ctx:
                        self.state.conversation.append(
                            {"role": "system", "content": _critical_ctx}
                        )

            adaptive_temperature = self._get_iteration_temperature(
                cfg, current_phase.value if current_phase else ""
            )
            adaptive_num_predict = self._get_iteration_num_predict(
                cfg, current_phase, adaptive_num_ctx
            )

            await self._enforce_char_budget(
                num_ctx=adaptive_num_ctx,
                num_predict=adaptive_num_predict,
            )

            _last_chunk_data = {}
            _vram_retries_this_iter = 0

            yield AgentEvent(
                type="progress",
                data={
                    "message": f"Waiting for model response (iteration {self.state.iteration})...",
                    "stage": "ollama_inference",
                },
            )

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
                    
                    # FIX 2026-03-31: Check context BEFORE LLM call to prevent hang
                    await self._check_and_reset_context()
                    
                    async for chunk in self.ollama.chat_stream(
                        messages=self._messages_for_ollama(),
                        tools=self._tools_ollama,
                        options={
                            "num_ctx": adaptive_num_ctx,
                            "temperature": adaptive_temperature,
                            "num_predict": adaptive_num_predict,

                            "num_keep": _safe_num_keep,

                            "repeat_penalty": self._cfg_float(
                                cfg, "ollama_repeat_penalty", 1.05),
                        },
                        think=self._should_use_thinking(cfg, current_phase),
                        stop_requested_fn=lambda: self._stop_requested,
                    ):
                        if hasattr(chunk, "model_dump"):
                            chunk_data = chunk.model_dump()
                        elif isinstance(chunk, dict):
                            chunk_data = chunk
                        else:
                            chunk_data = dict(chunk)

                        _last_chunk_data = chunk_data

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

                    if _last_chunk_data:

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

                    break
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

                            _new_ctx = 4096
                            _max_msgs = 20
                            _wait_s = 30

                        self._adaptive_num_ctx = _new_ctx
                        adaptive_num_ctx = _new_ctx

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
                        continue

                    elif _is_conn_refused and _stream_attempt < 4:

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

                        logger.warning(
                            "Ollama stream stalled/timed out — retrying once "
                            "(iteration=%d): %s",
                            self.state.iteration,
                            err_str[:120],
                        )
                        yield AgentEvent(
                            type="text",
                            data={
                                "content": (
                                    "\n[AUTO-RECOVERY] Ollama stream stalled "
                                    "(no tokens received). Retrying...\n"
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
                            "Ollama stream stalled twice — model stopped "
                            "generating tokens.\n"
                            "Fix: check `ollama serve` logs; increase "
                            "`ollama_chunk_timeout` in config if the model "
                            "just needs more time between tokens."
                        )
                    else:
                        error_msg = f"Model connection error: {err_str}"
                    logger.error("Ollama stream error: %s", stream_err)
                    yield AgentEvent(type="error", data={"message": error_msg})
                    yield AgentEvent(type="done", data={})
                    return

            if not content_acc and not tool_calls_acc and not thinking_acc:

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
                    continue

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

            content_acc, thinking_acc, tool_calls_acc, _has_task_complete = self._analyze_llm_output(
                current_phase=current_phase,
                content_acc=content_acc,
                thinking_acc=thinking_acc,
                tool_calls_acc=tool_calls_acc,
            )

            if not tool_calls_acc:
                self._no_tool_iterations += 1
                if _has_task_complete:
                    logger.info(
                        "Agent emitted [TASK_COMPLETE] — stopping.")

                    if self._has_scan_work():
                        save_session(self._session)
                    yield AgentEvent(type="done", data={})
                    return

                _force_tool_mode = bool(self.state.active_target)

                _retry_text_only = _force_tool_mode
                if _retry_text_only:
                    _max_text_only_retries = max(
                        3,
                        int(getattr(cfg, "agent_missing_tool_retry_limit", 2)) + 1,
                    )

                    _reflector_max = 2
                    if self._no_tool_iterations <= _reflector_max:
                        reflector_msg = self._build_reflector_message(
                            content_acc=content_acc,
                            attempt=self._no_tool_iterations,
                            phase=current_phase,
                        )

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

                    elif self._no_tool_iterations >= _max_text_only_retries:
                        watchdog_call = self._build_watchdog_tool_call(
                            content_acc=content_acc,
                            thinking_acc=thinking_acc,
                            phase=current_phase,
                        )
                        if self._watchdog_forced_calls >= 3:

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
                                save_session(self._session)
                            yield AgentEvent(type="error", data={"message": msg})
                            yield AgentEvent(type="done", data={})
                            return
                        elif watchdog_call:

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

                if not tool_calls_acc:
                    if self._session:
                        save_session(self._session)
                    yield AgentEvent(type="done", data={})
                    return

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

                self._watchdog_forced_calls = 0

            if not content_acc.strip():
                tool_names_str = ", ".join(
                    tc["function"]["name"] for tc in tool_calls_acc
                )
                yield AgentEvent(
                    type="text", data={"content": f"Executing: {tool_names_str}..."}
                )

            parallelizable_tools = _TOOLS_META.get(
                "parallelizable_tools", [])

            tool_groups: dict[str, list[tuple[int, dict, dict]]] = {}
            sequential_only: list[tuple[int, dict, dict]] = []

            for idx, tc in enumerate(tool_calls_acc):
                tn = tc["function"]["name"]
                args = self._normalize_tool_args(
                    tn, tc["function"]["arguments"], None
                )

                yield AgentEvent(
                    type="tool_start",
                    data={
                        "tool_id": str(idx),
                        "tool": tn,
                        "arguments": args},
                )

                is_parallel = False
                if tn == "execute":
                    cmd = args.get("command", "")
                    cmd_parts = cmd.split()

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

                        if "parallel" not in tool_groups:
                            tool_groups["parallel"] = []
                        tool_groups["parallel"].append((idx, tc, args))
                        is_parallel = True

                if not is_parallel:
                    sequential_only.append((idx, tc, args))

            all_results: dict[
                int, tuple
            ] = {}

            async def execute_single_tool(
                    idx: int, tc: dict, args: dict) -> tuple:
                tn = tc["function"]["name"]

                is_dup, dup_msg = self._is_duplicate_command(tn, args)
                if is_dup:
                    logger.info("Anti-repeat guard blocked duplicate: %s", tn)
                    return (
                        idx, tc, tn, args,
                        True,
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

                if tn == "execute":
                    self._apply_output_merge(args, s)

                return (idx, tc, tn, args, True, d, r, o, s)

            for _, group_tasks in tool_groups.items():
                if len(group_tasks) > 1:

                    tasks = [
                        asyncio.create_task(
                            execute_single_tool(idx, tc, args))
                        for idx, tc, args in group_tasks
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for (idx, tc, args), res in zip(group_tasks, results):

                        if isinstance(res, BaseException):
                            logger.error("Parallel tool error: %s", res)

                            tn = tc["function"]["name"]
                            all_results[idx] = (
                                idx, tc, tn, args, False, 0.0,
                                {"success": False, "error": str(res)},
                                None, False,
                            )
                        else:
                            all_results[res[0]] = res
                else:

                    idx, tc, args = group_tasks[0]
                    res = await execute_single_tool(idx, tc, args)
                    all_results[idx] = res

            for idx, tc, args in sequential_only:

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
                elif tn == "request_user_input":
                    # Rate limiting: prevent spamming user with input requests
                    import time as _time_mod
                    _now = _time_mod.time()
                    if _now - self._last_user_input_time < self._user_input_cooldown:
                        _remaining = self._user_input_cooldown - (_now - self._last_user_input_time)
                        logger.warning(
                            "request_user_input: rate limited. Please wait %.0fs before requesting user input again.",
                            _remaining
                        )
                        s, d, r, o = False, 0.0, {
                            "success": False,
                            "error": f"Rate limited. Please wait {int(_remaining)} seconds before requesting user input again.",
                            "retry_after": int(_remaining),
                        }, None
                    else:
                        import uuid as _uuid_mod
                        _req_id = str(_uuid_mod.uuid4())
                        _pre_evt = asyncio.Event()
                        self._user_input_event = _pre_evt
                        self._user_input_cancelled = False
                        self._user_input_value = ""
                        self._user_input_request_id = _req_id
                        self._user_input_prompt = args.get("prompt", "")
                        self._user_input_type = args.get("input_type", "text")
                        yield AgentEvent(
                            type="user_input_required",
                            data={
                                "request_id": _req_id,
                                "prompt": self._user_input_prompt,
                                "input_type": self._user_input_type,
                            },
                        )
                        s, d, r, o = await self._execute_request_user_input(
                            tn, args, request_id=_req_id, event=_pre_evt
                        )
                        self._last_user_input_time = _time_mod.time()
                    self.state.missing_tool_count = 0
                elif any(tn == t["function"]["name"] for t in (self._tools_ollama or [])):
                    out_queue: asyncio.Queue[str] = asyncio.Queue()

                    def _on_chunk(text: str) -> None:
                        out_queue.put_nowait(text)

                    t_task = asyncio.create_task(
                        self._execute_tool_and_record(
                            tn, args, on_output=_on_chunk)
                    )

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

                if tn == "execute":
                    self._apply_output_merge(args, s)
                all_results[idx] = (idx, tc, tn, args, True, d, r, o, s)

            async for _evt in self._finalize_tool_results(
                current_phase=current_phase,
                all_results=all_results,
                has_task_complete=_has_task_complete,
            ):
                yield _evt
            if getattr(self, "_iteration_terminated", False):
                return

        yield AgentEvent(
            type="error", data={"message": "Max tool iterations reached."}
        )
        yield AgentEvent(type="done", data={})

