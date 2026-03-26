"""Adaptive inference parameter helpers for AgentLoop.

Extracted from loop.py to keep that file manageable. Contains:
- _cfg_bool / _cfg_int / _cfg_float — typed config accessors
- _fit_num_predict_to_ctx — clamp output reservation to context window
- _get_iteration_num_predict / _get_adaptive_num_predict — per-iteration token budget
- _should_use_thinking — decide whether extended thinking is worth the VRAM
- _get_iteration_temperature — base temp or exploration temp based on state
"""
from __future__ import annotations

from typing import Any

from .pipeline import PipelinePhase


class _InferenceMixin:
    """Mixin: adaptive temperature, num_predict, and thinking-mode helpers."""

    # Tools that need minimal reasoning — reduce token budget to speed up iteration.
    _SHALLOW_TOOLS: frozenset[str] = frozenset({
        "list_files", "read_file", "create_file", "get_console_logs",
        "get_network_logs", "view_source", "caido_list_requests",
    })
    # Tools / phases that need maximum reasoning depth.
    _DEEP_TOOLS: frozenset[str] = frozenset({
        "advanced_fuzz", "deep_fuzz", "schemathesis_fuzz",
        "spawn_agent", "create_vulnerability_report", "code_analysis",
    })

    @staticmethod
    def _cfg_bool(cfg: Any, key: str, default: bool) -> bool:
        try:
            val = getattr(cfg, key, default)
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("1", "true", "yes", "on")
            return bool(val)
        except Exception:
            return default

    @staticmethod
    def _cfg_int(cfg: Any, key: str, default: int) -> int:
        try:
            return int(getattr(cfg, key, default))
        except Exception:
            return default

    @staticmethod
    def _cfg_float(cfg: Any, key: str, default: float) -> float:
        try:
            return float(getattr(cfg, key, default))
        except Exception:
            return default

    @staticmethod
    def _fit_num_predict_to_ctx(num_predict: int, num_ctx: int) -> int:
        """Clamp output reservation to fit inside the active context window.

        Ensures we always keep meaningful prompt/input space and avoids
        pathological settings (e.g. num_predict ~= num_ctx) that trigger
        aggressive truncation and unstable model behavior.
        """
        _ctx = max(1024, int(num_ctx))
        _requested = max(256, int(num_predict))
        _prompt_reserve = 1024 if _ctx >= 4096 else max(256, _ctx // 4)
        _max_by_prompt = max(256, _ctx - _prompt_reserve)
        _max_by_ratio = max(512, int(_ctx * 0.40))
        return max(256, min(_requested, _max_by_prompt, _max_by_ratio))

    @staticmethod
    def _fit_num_keep_to_ctx(num_keep: int, num_ctx: int, num_predict: int) -> int:
        """Clamp num_keep so it never exceeds the active context envelope.

        After VRAM recovery, num_ctx may shrink aggressively (e.g. 4096). If
        num_keep remains high (e.g. 8192), Ollama can reject/struggle with the
        request and recovery loops fail repeatedly.
        """
        _ctx = max(1024, int(num_ctx))
        _predict = max(0, int(num_predict))
        _requested = max(0, int(num_keep))
        _max_by_ctx = max(0, _ctx - 256)
        _max_by_predict = max(0, _ctx - _predict - 256)
        return min(_requested, _max_by_ctx, _max_by_predict)

    def _get_iteration_num_predict(
        self, cfg: Any, current_phase: Any, num_ctx: int
    ) -> int:
        """Compute the real num_predict used this iteration.

        Combines phase/tool adaptivity, crash-time cap, and context-fit guardrails.
        """
        _phase_name = current_phase.value if current_phase else "RECON"
        _requested = self._get_adaptive_num_predict(cfg, _phase_name)
        if self._adaptive_num_predict_cap > 0:
            _requested = min(_requested, self._adaptive_num_predict_cap)
        return self._fit_num_predict_to_ctx(_requested, num_ctx)

    def _should_use_thinking(
        self, cfg: Any, current_phase: Any
    ) -> bool:
        """Decide whether to enable thinking for this iteration.

        Thinking is expensive: ~1500 tokens and 1-3s overhead per iteration.
        It's only needed when the model must reason deeply — not for routine
        RECON tool calls like 'run subfinder'.

        Rules:
        - Always OFF if model/config disables it globally.
        - Always ON in ANALYSIS and EXPLOIT (complex reasoning required).
        - Always ON during stagnation, recovery, or repeated failures.
        - Always ON for deep tools (advanced_fuzz, spawn_agent, etc.).
        - RECON / REPORT routine iterations: OFF after iter 8 to save tokens.
        """
        if not (
            self._cfg_bool(cfg, "ollama_enable_thinking", True)
            and self.ollama.supports_thinking
        ):
            return False

        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)
        _is_struggling = (
            self._stagnation_iterations >= stagnation_threshold
            or self._recovery_force_tool_calls > 0
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
            or self._watchdog_forced_calls > 0
        )

        # CTF mode: thinking is expensive VRAM-wise on 122B models.
        # Only think when genuinely stuck or at periodic checkpoints (every 5 iter).
        # Routine CTF iterations (curl, read, enumerate) do not need deep reasoning.
        if self._ctf_mode:
            if _is_struggling:
                return True
            last_tool = self._recent_tool_names[-1] if self._recent_tool_names else ""
            if last_tool in self._DEEP_TOOLS:
                return True
            # Periodic thinking every 5 iterations to reassess strategy
            return self.state.iteration % 5 == 0

        # Normal mode: always think for ANALYSIS and EXPLOIT
        if current_phase and current_phase in (
            PipelinePhase.ANALYSIS, PipelinePhase.EXPLOIT
        ):
            return True

        # Always think when struggling or in recovery
        if _is_struggling:
            return True

        # Always think for deep tools
        last_tool = self._recent_tool_names[-1] if self._recent_tool_names else ""
        if last_tool in self._DEEP_TOOLS:
            return True

        # RECON / REPORT: disable thinking after warm-up (iter > 8)
        # to save tokens per iteration on routine tool calls.
        if self.state.iteration > 8:
            return False

        return True

    def _get_adaptive_num_predict(self, cfg: Any, phase: str) -> int:
        """Return an adaptive num_predict based on phase complexity and last tool.

        SHALLOW (fast iteration):  4 096 tokens   — file ops, listing, log reads
        MEDIUM  (default):         8 192 tokens   — recon, analysis tasks
        DEEP    (max reasoning):  16 384 tokens   — exploit dev, reporting, stagnation
        CTF mode caps at 8 192 to prevent thinking-block VRAM explosion.
        """
        base = self._cfg_int(cfg, "ollama_num_predict", 32768)
        last_tool = self._recent_tool_names[-1] if self._recent_tool_names else ""
        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)

        # CTF mode: cap tightly — each iteration must be fast and lean.
        # Large thinking blocks in EXPLOIT phase are the primary VRAM killer.
        if self._ctf_mode:
            if (
                self._stagnation_iterations >= stagnation_threshold
                or self._consecutive_failures >= 2
            ):
                return min(base, 8192)   # deep think only when truly stuck
            return min(base, 4096)       # routine CTF iteration: minimal budget

        # Normal mode: tiered budget
        if (
            self._stagnation_iterations >= stagnation_threshold
            or phase in ("EXPLOIT", "REPORT")
            or last_tool in self._DEEP_TOOLS
        ):
            return min(base, 16384)   # deep — capped to prevent VRAM OOM

        if last_tool in self._SHALLOW_TOOLS:
            return min(base, 4096)    # shallow: fast

        # ANALYSIS or RECON with non-trivial tools — medium budget
        return min(base, 8192)

    def _get_iteration_temperature(self, cfg: Any) -> float:
        base_temp = self._cfg_float(cfg, "ollama_temperature", 0.15)
        if not self._cfg_bool(cfg, "agent_exploration_mode", True):
            return base_temp
        exploration_temp = self._cfg_float(
            cfg, "agent_exploration_temperature", 0.35
        )
        stagnation_threshold = self._cfg_int(cfg, "agent_stagnation_threshold", 2)
        if (
            self._stagnation_iterations >= stagnation_threshold
            or self._consecutive_failures >= 2
            or self._no_tool_iterations >= 1
        ):
            return max(base_temp, exploration_temp)
        return base_temp
