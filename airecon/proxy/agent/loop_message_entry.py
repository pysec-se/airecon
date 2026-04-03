from __future__ import annotations

from ..config import get_config, get_workspace_root
from ..system import _is_ctf_target, auto_load_skills_for_message
from .file_reference import (
    build_injection_message,
    parse_refs,
    resolve_ref,
    strip_refs,
    workspace_name_for_ref,
)
from .loop_policy import (
    build_full_recon_kickoff_message,
    is_simple_target_kickoff,
    normalize_recon_mode,
    should_autostart_full_recon,
    should_preserve_active_target_for_subdomain,
)
from .models import MAX_TOOL_ITERATIONS
from .pipeline import PipelineEngine, PipelinePhase
from .session import (
    SessionData,
    find_prior_session,
    merge_prior_findings,
    session_to_context,
)
from .loop_exploration import _MEANINGFUL_EVIDENCE_THRESHOLD
import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("airecon.agent")


class _MessageEntryMixin:
    async def _prepare_message_context(self, user_message: str):

        _file_refs = parse_refs(user_message)
        if _file_refs:
            user_message = strip_refs(user_message, _file_refs)

        all_targets = self._extract_targets_from_text(user_message)
        extracted_target = all_targets[0] if all_targets else None

        if not self._tools_ollama:

            await self.initialize(
                target=extracted_target,
                user_message=user_message,
            )
        else:

            if not self._ctf_mode and extracted_target:
                if _is_ctf_target(extracted_target, user_message=None):
                    self._ctf_mode = True
                    if self._override_max_iterations is None:
                        self._override_max_iterations = self._CTF_MAX_ITERATIONS
                    if self.pipeline:
                        self.pipeline.set_ctf_mode(True)

                    if self._adaptive_num_ctx == 0:
                        self._adaptive_num_ctx = get_config().ollama_num_ctx_small
                    logger.info(
                        "CTF mode activated mid-session for target=%r — ctx=%d",
                        extracted_target, self._adaptive_num_ctx,
                    )

        if extracted_target:
            _current = self.state.active_target
            if not should_preserve_active_target_for_subdomain(
                extracted_target=extracted_target,
                current_active_target=_current,
            ):
                self.state.active_target = extracted_target

        cfg = get_config()

        if _file_refs and not self.state.active_target:
            self.state.active_target = workspace_name_for_ref(
                _file_refs[0]
            )

        # Config-driven agent recon mode: standard vs full
        # - standard: Do NOT auto-expand simple target to full recon (user intent must be explicit)
        # - full: Auto-expand simple target to comprehensive recon (legacy autostart)
        _recon_mode = normalize_recon_mode(
            getattr(cfg, "agent_recon_mode", "standard")
        )
        if (
            isinstance(extracted_target, str)
            and should_autostart_full_recon(
                cfg=cfg,
                user_message=user_message,
                extracted_target=extracted_target,
            )
        ):
            logger.info(
                "Auto-starting deep recon (agent_recon_mode=%s) for %s",
                _recon_mode,
                extracted_target,
            )
            user_message = build_full_recon_kickoff_message(extracted_target)

        # In STANDARD mode, non-target-only requests are treated as strict scope.
        # This prevents autonomous expansion into full recon when user asks for
        # a focused task (e.g. only one recon slice).
        _simple_kickoff = is_simple_target_kickoff(user_message, extracted_target)
        self._scope_lock_active = bool(_recon_mode == "standard" and not _simple_kickoff)
        self._scope_lock_brief = user_message.strip()[:500] if self._scope_lock_active else ""
        if self._scope_lock_active:
            self.state.conversation.append(
                {
                    "role": "system",
                    "content": (
                        "[SYSTEM: STRICT_SCOPE_MODE] "
                        "The current user request is scoped/focused. "
                        "Do NOT widen into broad/full recon, port sweeps, or unrelated phases. "
                        "Execute only actions directly required by the explicit user request."
                    ),
                }
            )

        EPHEMERAL_PREFIXES = (
            "[SYSTEM: WORKSPACE",
            "[SYSTEM: ACTIVE_TARGET",
            "[SYSTEM: ADDITIONAL_TARGETS",
            "[SYSTEM: OBJECTIVE FOCUS",
            "<objective_focus",
            "[SYSTEM: PHASE GATE",
            "[SYSTEM: AGGRESSIVE EXPLORATION",
            "[SYSTEM: QUALITY SCOREBOARD",
            "[SYSTEM: RECOVERY STATE",
            "<reflector ",
            "<mentor_analysis>",
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
        
        # FIX 2026-03-31: Check Ollama context and reset with summary if needed
        if self.state.iteration % 10 == 0:
            self._check_ollama_context_pressure()

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

            if not self._session:
                self._session = SessionData(
                    target=self.state.active_target)
                self._sync_token_usage_from_session()
                self.pipeline = PipelineEngine(self._session)
                if self._ctf_mode and self.pipeline:
                    self.pipeline.set_ctf_mode(True)
            elif self._session.target != self.state.active_target:

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

            if (
                self._session
                and self._session.scan_count == 0
                and not getattr(self._session, "_prior_merged", False)
            ):
                prior = find_prior_session(self.state.active_target)
                if prior and prior.session_id != self._session.session_id:
                    merge_prior_findings(self._session, prior)

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

                self._session._prior_merged = True

            if self._session and self._session.scan_count > 0:
                session_ctx = session_to_context(self._session)
                self.state.conversation.append(
                    {
                        "role": "system",
                        "content": session_ctx,
                    }
                )

                if self.pipeline:
                    _resumed_phase = self.pipeline.get_current_phase()
                    self._sync_phase_objectives(_resumed_phase)
                    self._update_objectives_from_session(_resumed_phase)

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

        _cumulative = self.state.token_usage.get("cumulative", 0)
        _CUMULATIVE_SOFT_CAP = 80000
        _CUMULATIVE_HARD_CAP = 100000

        if _cumulative > _CUMULATIVE_HARD_CAP:
            logger.error(
                "Cumulative tokens (%d) exceeded hard cap (%d) — forcing emergency truncation",
                _cumulative, _CUMULATIVE_HARD_CAP,
            )

            _system_msgs = [
                m for m in self.state.conversation
                if m.get("role") == "system"
            ]
            _non_system = [
                m for m in self.state.conversation
                if m.get("role") != "system"
            ]
            _keep_recent = max(int(len(_non_system) * 0.20), 6)
            _recent_msgs = _non_system[-_keep_recent:]
            _prev_total = len(self.state.conversation)
            self.state.conversation = _system_msgs + _recent_msgs

            self.state.token_usage["cumulative"] = int(_cumulative * 0.30)

            logger.warning(
                "Emergency truncation complete: %d messages → %d "
                "(sys=%d kept, non-sys %d → %d), cumulative %d → %d tokens",
                _prev_total, len(self.state.conversation),
                len(_system_msgs), len(_non_system), len(_recent_msgs),
                _cumulative, self.state.token_usage["cumulative"],
            )
        elif _cumulative > _CUMULATIVE_SOFT_CAP:
            logger.warning(
                "Cumulative tokens (%d) approaching soft cap (%d) — will truncate soon",
                _cumulative, _CUMULATIVE_SOFT_CAP,
            )

        _skill_phase = self._skill_phase_for_message_start()

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

            if self._session:
                for skill_rel in loaded_skills:
                    if skill_rel not in self._session.loaded_skills:
                        self._session.loaded_skills.append(skill_rel)

        if skill_context:

            self.state.conversation.append(
                {"role": "system", "content": skill_context, "iteration": self.state.iteration}
            )

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

        if (
            self._session
            and getattr(self._session, "current_phase", "") == "COMPLETE"
            and self.pipeline
        ):
            self.pipeline.set_phase(PipelinePhase.RECON)
            self.state.objective_queue.clear()

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

        return cfg
