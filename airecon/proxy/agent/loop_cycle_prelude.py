from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict as _asdict
from pathlib import Path
from typing import Any

from .chain_planner import ChainStep as _ChainStep
from .chain_planner import ExploitChain as _ExploitChain
from .chain_planner import build_chain_context, plan_chains
from .pipeline import PipelinePhase
from .session import save_session, session_to_context

logger = logging.getLogger("airecon.agent")

try:
    from ..server import _trace_chat_event
except (ImportError, ValueError):
    def _trace_chat_event(*args, **kwargs):
        pass


def _chain_step_to_text(step: Any) -> str:
    if isinstance(step, str):
        return step
    if isinstance(step, dict):
        return str(
            step.get("description")
            or step.get("name")
            or step.get("tool_hint")
            or step.get("step")
            or "step"
        )
    return str(step)


class _CyclePreludeMixin:
    async def _run_iteration_housekeeping(self, cfg: Any, current_phase: Any) -> None:
        # Inject output file manifest at iteration 1 and 3 so the AI knows
        # what artifacts already exist BEFORE running any discovery tools.
        if self.state.iteration in (1, 3) and self._session and not self._ctf_mode:
            try:
                from ..config import get_workspace_root as _gws

                _workspace = _gws() / self._session.target
                _manifest_parts: list[str] = []
                for _subdir in ("output", "recon", "scan_results", "findings", "reports", "tools"):
                    _d = _workspace / _subdir
                    if _d.is_dir():
                        _files = sorted([f.name for f in _d.iterdir() if f.is_file()])[:15]
                        if _files:
                            _manifest_parts.append(f"{_subdir}/: {', '.join(_files)}")
                if _manifest_parts:
                    _manifest = (
                        "[SYSTEM: OUTPUT FILE MANIFEST — these artifacts already exist]\n"
                        "READ existing files with read_file before re-running any scan.\n"
                        "DO NOT re-scan if the information you need is already in these files.\n" +
                        "\n".join(f"  {p}" for p in _manifest_parts)
                    )
                    self.state.conversation.append(
                        {"role": "system", "content": _manifest}
                    )
                    logger.info(
                        "Output file manifest injected at iteration %d (%d dirs)",
                        self.state.iteration,
                        len(_manifest_parts),
                    )
            except Exception as _manifest_err:
                logger.debug("File manifest injection failed: %s", _manifest_err)

        if self.state.iteration % 10 == 0:
            self._check_ollama_context_pressure()

        self._enforce_scope_target_integrity()

        if (
            self._session
            and self.state.iteration % self._conversation_save_interval == 0
            and self.state.iteration != self._last_conversation_save_iteration
        ):
            self._sync_conversation_to_session()
            try:

                self._schedule_token_usage_snapshot_save()
            except Exception as _save_err:
                logger.debug("Failed to save conversation at iteration %d: %s",
                           self.state.iteration, _save_err)
            self._last_conversation_save_iteration = self.state.iteration
            logger.debug(
                f"Conversation auto-saved at iteration {self.state.iteration}"
            )

        if (
            self._session
            and self._session.target
            and self.state.iteration % self._memory_save_interval == 0
            and self.state.iteration != self._last_memory_save_iteration
        ):
            self._save_to_memory_realtime()
            self._last_memory_save_iteration = self.state.iteration

        _memory_health_interval = max(1, int(getattr(self, "_memory_health_interval", 10) or 10))
        if (
            self._session
            and self._session.target
            and self.state.iteration > 0
            and self.state.iteration % _memory_health_interval == 0
            and self.state.iteration != getattr(self, "_last_memory_health_check_iteration", -1)
        ):
            self._check_memory_brain_health()
            self._last_memory_health_check_iteration = self.state.iteration

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

        if self._prev_phase is not None and current_phase != self._prev_phase:
            logger.debug(
                "Phase transition %s → %s: stagnation counter reset.",
                self._prev_phase.value,
                current_phase.value,
            )
            self._stagnation_iterations = 0
            self._recent_tool_names.clear()
        self._prev_phase = current_phase

        # Memory-based pattern learning: inject tech-matched patterns every 8 iterations
        if (
            self._session
            and self.state.iteration > 0
            and self.state.iteration % 8 == 0
        ):
            try:
                from ..memory import get_memory_manager

                _mem = get_memory_manager()
                _techs = getattr(self._session, "technologies", {}) or {}
                _tech_names = list(_techs.keys())[:3] if _techs else []

                _learned_patterns = _mem.get_patterns(
                    target_tech=_tech_names[0] if _tech_names else None,
                    limit=5,
                    min_success_rate=0.60,
                )
                _similar_findings = _mem.get_similar_findings(
                    target=self._session.target, limit=5
                )

                if _learned_patterns:
                    _p_lines = ["[SYSTEM: LEARNED PATTERNS — proven from past sessions]"]
                    for _p in _learned_patterns[:4]:
                        _desc = str(_p.get("description", ""))[:120]
                        _sr = float(_p.get("success_rate", 0)) * 100
                        _eff = float(_p.get("effectiveness_score", _sr))
                        _tools_used = _p.get("commands_used", [])
                        _tools_str = (
                            f" used: {', '.join(str(x) for x in _tools_used[:3])}"
                            if _tools_used
                            else ""
                        )
                        _p_lines.append(
                            f"- {_desc} (success={_sr:.0f}%, effectiveness={_eff:.0f}){_tools_str}"
                        )
                    self.state.conversation = [
                        m
                        for m in self.state.conversation
                        if not str(m.get("content", "")).startswith(
                            "[SYSTEM: LEARNED PATTERNS"
                        )
                    ]
                    self.state.conversation.append(
                        {"role": "system", "content": "\n".join(_p_lines)}
                    )
                    logger.info(
                        "Learned patterns injected: %d (tech=%s)",
                        len(_learned_patterns),
                        ", ".join(_tech_names) if _tech_names else "generic",
                    )

                if _similar_findings and self.state.iteration <= 16:
                    _f_lines = [
                        "[SYSTEM: SIMILAR TARGET FINDINGS — from past sessions on subdomains]"
                    ]
                    for _f in _similar_findings[:3]:
                        _desc = str(_f.get("description", ""))[:100]
                        _sev = str(_f.get("severity", "Info"))
                        _ftype = str(_f.get("finding_type", "unknown"))
                        _f_lines.append(f"- [{_sev}] {_ftype}: {_desc}")
                    self.state.conversation.append(
                        {"role": "system", "content": "\n".join(_f_lines)}
                    )
                    logger.info(
                        "Similar findings injected: %d", len(_similar_findings)
                    )
            except Exception as _pattern_err:
                logger.debug("Pattern learning injection failed: %s", _pattern_err)

        current_time = time.time()
        if self._last_request_time > 0:
            response_time = current_time - self._last_request_time
            self._request_times.append(response_time)

            avg_response_time = sum(self._request_times) / len(self._request_times) if self._request_times else 0

            if avg_response_time > 30:
                logger.warning(
                    "Slow response detected (avg: %.1fs), implementing throttling",
                    avg_response_time,
                )

                await asyncio.sleep(min(avg_response_time / 10, 2.0))

        self._last_request_time = current_time

        if not getattr(self, "_scope_lock_active", False):
            self._sync_phase_objectives(current_phase)
            self._update_objectives_from_session(current_phase)

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

                        self.state.exploit_chains.append(_asdict(_nc))
                        logger.info(
                            "Exploit chain planned: %s (basis: %s)",
                            _nc.name, _nc.vuln_basis[:60],
                        )

                    _ec_objs: list[_ExploitChain] = []
                    for _cd in self.state.exploit_chains:
                        try:

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

        trace_id = getattr(self, "_current_trace_id", None)
        if trace_id:
            _trace_chat_event(trace_id, "iteration_prepare", iteration=self.state.iteration)

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

            self.state.planned_tools.clear()

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
            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith(
                    "[SYSTEM: MANDATORY PLAN REVISION"
                )
            ]
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

        if self.state.iteration > 1 and self.state.iteration % 5 == 0:
            session_info = ""
            pipeline_prompt = ""

            if self._session:
                s = self._session

                if self.pipeline:
                    self.pipeline._current_iteration = self.state.iteration

                if (
                    self.pipeline
                    and not getattr(self, "_scope_lock_active", False)
                    and self.pipeline.should_transition()
                ):
                    _prev_phase = self.pipeline.get_current_phase()
                    new_phase = self.pipeline.transition()
                    if new_phase:
                        pipeline_prompt = self.pipeline.get_transition_prompt(
                            new_phase)

                        self._compact_phase_context(
                            _prev_phase.value if _prev_phase else "RECON"
                        )

                        from airecon.proxy.agent.pipeline import (
                            PipelinePhase as _PP,
                        )
                        if new_phase == _PP.EXPLOIT:
                            self._inject_exploit_vuln_context()

                        self._stagnation_iterations = 0
                        logger.debug(
                            "Phase transition to %s — stagnation counter reset",
                            new_phase.value,
                        )
                elif self.pipeline:
                    pipeline_prompt = "\n" + self.pipeline.get_phase_prompt()

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

                    session_info = "\n" + session_to_context(s)

                    _app_ctx = s.app_model.build_context()
                    if _app_ctx:
                        session_info += "\n" + _app_ctx

            self.state.conversation = [
                msg
                for msg in self.state.conversation
                if not msg.get("content", "").startswith(
                    "[SYSTEM: EXECUTION CHECKPOINT"
                )
            ]
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

        if self._ctf_mode:
            _max_itr = self._override_max_iterations or self._CTF_MAX_ITERATIONS
            _m33 = max(5, _max_itr // 3)
            _m66 = max(10, (_max_itr * 2) // 3)
            if self.state.iteration in (_m33, _m66):
                _pct = 33 if self.state.iteration == _m33 else 66

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

        if self.state.iteration > 1 and self.state.iteration % 10 == 0:
            vuln_chaining_prompt = ""
            correlation_prompt = ""
            expert_testing_prompt = ""

            if self._session:
                s = self._session

                if s.open_ports or s.technologies or s.injection_points:
                    from ..correlation import (
                        run_correlation,
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
                                steps_str = " → ".join(_chain_step_to_text(s) for s in steps)
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
                                steps_str = " → ".join(_chain_step_to_text(s) for s in steps)
                                corr_lines.append(
                                    f"- [{severity}] ATTACK CHAIN DETECTED "
                                    f"({name}): {steps_str}"
                                )

                            elif vuln_type == "synthesized_chain":
                                title = corr.get("title", "?")
                                confidence = corr.get("confidence", 0.0)
                                steps = corr.get("steps", [])
                                steps_str = " → ".join(_chain_step_to_text(s) for s in steps[:5])
                                corr_lines.append(
                                    f"- [{severity}] SYNTHESIZED CHAIN "
                                    f"(conf={confidence:.0%}) {title}"
                                    + (f": {steps_str}" if steps_str else "")
                                )

                            else:
                                corr_lines.append(
                                    f"- [{severity}] Unknown Correlation: {corr}")

                        correlation_prompt = "\n".join(corr_lines)

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

        if self.state.iteration % 5 == 0 and self._has_scan_work():
            save_session(self._session)

        _presummary_ratio = (
            self.state.token_usage.get("used", 0)
            / max(self._adaptive_num_ctx or cfg.ollama_num_ctx, 1)
        )
        _pressure_compress = (
            self.state.iteration > 0
            and _presummary_ratio >= 0.35
        )
        _compress_now = (
            self.state.iteration > 0 and
            (_presummary_ratio >= 0.30 or self.state.iteration % 5 == 0)
        )
        if _compress_now:
            self._compress_old_tool_outputs(aggressive=_pressure_compress or self.state.iteration > 50)
            pinned = self._build_compressed_findings_summary()
            if pinned:
                self.state.conversation = [
                    m for m in self.state.conversation
                    if not m.get("content", "").startswith("[SYSTEM: PINNED CONTEXT")
                ]
                self.state.conversation.append({
                    "role": "system",
                    "content": pinned,
                })

        _cur_ctx_limit = self._adaptive_num_ctx or cfg.ollama_num_ctx
        _cur_num_predict = self._get_iteration_num_predict(
            cfg, current_phase, _cur_ctx_limit
        )

        _cur_effective_ctx = max(1024, _cur_ctx_limit - _cur_num_predict)
        _cur_token_ratio = (
            self.state.token_usage.get("used", 0) / max(_cur_effective_ctx, 1)
        )
        _early_pressure = _cur_token_ratio >= 0.40
        _aggressive = self._ctf_mode or _early_pressure or self.state.iteration > 100

        if self.state.iteration % 5 == 0 or _aggressive:

            if self.state.iteration >= 20:
                self._prune_stale_skills(max_age_iterations=10)

            if hasattr(self.state, 'token_usage'):
                self.state.token_usage["used"] = self._recompute_used_tokens_from_conversation()

            current_phase = self._get_current_phase().value if self._get_current_phase() else "RECON"

            _compress_ctx = min(8192, _cur_ctx_limit // 4)
            try:
                await self.state.compress_with_llm(
                    self.ollama, keep_recent=30,
                    num_ctx=_compress_ctx, num_predict=1024,
                    phase=current_phase,
                )

                self.state.token_usage["used"] = self._recompute_used_tokens_from_conversation()
                logger.info(
                    "Compression: token_usage after compression = %d",
                    self.state.token_usage["used"]
                )
            except Exception as compress_err:

                logger.warning(
                    "LLM compression failed (%s) — using aggressive truncate",
                    str(compress_err)[:100],
                )
                self.state.conversation = self.state.conversation[:50]

            self.state.token_usage["used"] = self._recompute_used_tokens_from_conversation()

            _token_used = self.state.token_usage.get("used", 0)
            _ctx_limit = self._adaptive_num_ctx or cfg.ollama_num_ctx
            if _token_used > _ctx_limit * 0.8:
                logger.warning(
                    "Token limit exceeded (%d/%d) - forcing aggressive truncation",
                    _token_used, _ctx_limit
                )
                self.state.conversation = self.state.conversation[:40]

            critical_context = self._build_critical_findings_context()

            if self.state.iteration < 100:
                _max_msgs = 150
            elif self.state.iteration < 200:
                _max_msgs = 120
            elif self.state.iteration < 300:
                _max_msgs = 100
            else:
                _max_msgs = 80
            self.state.truncate_conversation(max_messages=_max_msgs)

            if critical_context:
                self.state.conversation.append(
                    {"role": "system", "content": critical_context}
                )

        if self.state.iteration > 1 and self.state.iteration % 10 == 0:

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
