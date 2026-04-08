from __future__ import annotations

import logging
import re
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from ..system import auto_load_skills_for_technologies
from .loop_exploration import _get_meaningful_evidence_threshold
from .loop_phase_mentor import maybe_inject_mentor_analysis
from .models import AgentEvent
from .output_parser import parse_tool_output
from .session import save_session, update_from_parsed_output
from .waf_detector import (
    build_waf_bypass_context,
    detect_waf_from_response,
    merge_waf_profiles,
    rank_bypass_strategies,
)

logger = logging.getLogger("airecon.agent")

# Static asset extensions that should NOT be fuzzed individually
# But their PARENT DIRECTORY might be worth fuzzing!
# Loaded from file_extensions.json (was hardcoded — now single source of truth)
def _load_pure_static_exts() -> frozenset[str]:
    """Load static asset extensions from file_extensions.json."""
    try:
        from airecon.proxy.data_loader import load_file_extensions
        data = load_file_extensions()
        exts = data.get("static", [])
        return frozenset(str(e).strip().lower() for e in exts if str(e).strip())
    except Exception as e:
        logging.getLogger("airecon.agent.loop_cycle_post").warning(
            "Failed to load static extensions from JSON: %s", e
        )
        return frozenset()


_PURE_STATIC_EXTS: frozenset[str] = _load_pure_static_exts()

# JS files are GOLD — do NOT block analysis
# PDFs can leak info — do NOT block entirely


def _detect_static_asset_abuse(tool_name: str, arguments: dict) -> str | None:

    cmd = ""
    target_url = ""

    if tool_name == "execute":
        cmd = arguments.get("command", "").lower()
        url_match = re.search(r"https?://[^\s\"'<>|;&]+", cmd)
        if url_match:
            target_url = url_match.group(0)

    elif tool_name in ("quick_fuzz", "advanced_fuzz", "deep_fuzz"):
        target_url = arguments.get("target", arguments.get("url", "")).lower()

    if not target_url:
        return None

    # Check if URL is a pure static asset
    try:
        parsed = urlparse(target_url)
        path = parsed.path.rstrip("/")
        last_segment = path.rsplit("/", 1)[-1] if "/" in path else path
        if "." in last_segment:
            ext = last_segment.rsplit(".", 1)[-1].lower()
            if ext in _PURE_STATIC_EXTS:
                # Extract parent directory for fuzzing suggestion
                parent_dir = target_url.rsplit("/", 1)[0] + "/"
                return (
                    f"[STATIC ASSET NOTICE] You are testing '{target_url}' which is a "
                    f"static asset file (.{ext}). The file itself has ZERO attack surface.\n\n"
                    f"BUT the directory is fuzzable! Try:\n"
                    f"  - Directory fuzzing: ffuf -u {parent_dir}FUZZ -w wordlist.txt\n"
                    f"  - File discovery: Look for .php, .asp, .jsp, .html, .json in that path\n"
                    f"  - Hidden files: .env, .git/, backup files, config files\n\n"
                    f"SKIP individual .{ext} files. Fuzz the directory instead:\n"
                    f"  {parent_dir}"
                )
            # JS files — explicitly encourage analysis
            if ext in ("js", "jsx", "ts", "tsx", "mjs"):
                return (
                    f"[JS FILE RECON] .js/.ts files are GOLD for recon! "
                    f"Instead of fuzzing the JS file itself, analyze it for:\n"
                    f"  - API routes: grep -E 'api|/v[0-9]+|/graphql' {last_segment}\n"
                    f"  - API keys/secrets: grep -iE 'key|secret|token|password|auth' {last_segment}\n"
                    f"  - Internal endpoints: grep -oE 'https?://[^ \"\\']+' {last_segment}\n"
                    f"  - Source map: Check for {last_segment}.map for full source reconstruction\n"
                    f"  - Use linkfinder/jsleak for automated JS analysis"
                )
    except Exception as exc:
        logger.debug("Static asset abuse detection parse error: %s", exc)

    return None


class _CyclePostMixin:
    def _check_static_asset_abuse(
        self, tool_name: str, arguments: dict, success: bool
    ) -> str | None:
        return _detect_static_asset_abuse(tool_name, arguments)

    async def _finalize_tool_results(
        self,
        current_phase: Any,
        all_results: dict[int, tuple[Any, ...]],
        has_task_complete: bool,
    ) -> AsyncIterator[AgentEvent]:
        self._iteration_terminated = False
        if True:
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
                    arg_error = result.get("error", "Unknown validation error")
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
                                "active": bool(getattr(self, "_caido_available", False))
                                or (
                                    self.state.tool_counts.get("caido_send_request", 0)
                                    + self.state.tool_counts.get("caido_automate", 0)
                                )
                                > 0,
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
                            "active": bool(getattr(self, "_caido_available", False))
                            or (
                                self.state.tool_counts.get("caido_send_request", 0)
                                + self.state.tool_counts.get("caido_automate", 0)
                            )
                            > 0,
                            "findings_count": (
                                self.state.tool_counts.get("caido_send_request", 0)
                                + self.state.tool_counts.get("caido_automate", 0)
                            ),
                        },
                    },
                )
                self._track_tool_usage(tool_name, arguments)

                _duration = float(
                    result.get("duration", 0.0) if isinstance(result, dict) else 0.0
                )
                _output_size = len(
                    str(result.get("stdout", "") or result.get("result", ""))
                    if isinstance(result, dict)
                    else ""
                )
                self._record_tool_to_memory(
                    tool_name=tool_name,
                    success=bool(success),
                    duration=_duration,
                    output_size=_output_size,
                )

                if success:
                    self._consecutive_failures = 0
                    self.state.missing_tool_count = 0
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

                # Anti-hallucination guard: detect fuzzing/testing of static assets
                if tool_name in ("execute", "quick_fuzz", "advanced_fuzz", "deep_fuzz"):
                    _static_guard_note = self._check_static_asset_abuse(
                        tool_name, arguments, success
                    )
                    if _static_guard_note:
                        content_str = _static_guard_note + "\n\n" + content_str

                if self.pipeline:
                    phase_warn = self.pipeline.check_tool_phase_fit(tool_name)
                    if phase_warn:
                        content_str = phase_warn + "\n\n" + content_str
                phase_gate_note = self._build_phase_gate_note(tool_name, success)
                if phase_gate_note:
                    content_str = phase_gate_note + "\n\n" + content_str

                if success and tool_name in ("web_search", "browser_action"):
                    content_str += (
                        "\n\n[SYSTEM: MANDATORY FILE SAVE]\n"
                        f"You just executed `{tool_name}` successfully. "
                        "You are STRICTLY FORBIDDEN from keeping these results only in memory. "
                        "You MUST immediately use the `create_file` tool to save these findings "
                        "(URLs, text content, view_source, or console_logs) into the `output/` directory "
                        "(e.g., `output/dork_results.txt` or `output/source.txt`). "
                        "Do NOT proceed until this data is saved to disk!"
                    )

                _SESSION_UPDATE_TOOLS = (
                    "execute",
                    "browser_action",
                    "quick_fuzz",
                    "code_analysis",
                )
                if success and tool_name in _SESSION_UPDATE_TOOLS and self._session:
                    stdout = result.get("stdout", "") or result.get("result", "") or ""
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

                        _new_techs = {
                            k: v
                            for k, v in self._session.technologies.items()
                            if k not in _techs_before
                        }
                        if _new_techs:
                            _tech_skill_ctx, _tech_names = (
                                auto_load_skills_for_technologies(
                                    _new_techs,
                                    already_loaded=self._loaded_tech_skill_paths,
                                )
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
                    if float(e.get("confidence", 0.0))
                    >= _get_meaningful_evidence_threshold()
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
                    if float(e.get("confidence", 0.0))
                    >= _get_meaningful_evidence_threshold()
                )
                self.state.record_tool_outcome(
                    phase_after_tool.value,
                    tool_name,
                    success=bool(success),
                    meaningful_evidence_delta=max(
                        0, meaningful_after - meaningful_before
                    ),
                )

                # ── Intelligence: Adaptive Learning ────────────────────────
                if hasattr(self, "_record_adaptive_learning"):
                    self._record_adaptive_learning(
                        tool_name=tool_name,
                        arguments=arguments,
                        result=result,
                        success=bool(success),
                        duration=duration,
                        phase=phase_after_tool.value,
                    )

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

                            _match_token = tool_name.lower()
                            if _match_token == "execute" and isinstance(  # nosec B105
                                arguments, dict
                            ):
                                _raw_cmd = str(arguments.get("command", "")).strip()
                                _stripped = re.sub(
                                    r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                                ).strip()
                                _binary = (
                                    _stripped.split()[0].lower() if _stripped else ""
                                )
                                _shell_builtins = {
                                    "cd",
                                    "echo",
                                    "export",
                                    "source",
                                    ".",
                                    "for",
                                    "while",
                                    "if",
                                }
                                if _binary and _binary not in _shell_builtins:
                                    _match_token = _binary
                            if _hint and (
                                _match_token in _hint or tool_name.lower() in _hint
                            ):
                                _cur_step["status"] = "done"
                                _next_idx = _cs_idx + 1
                                _chain_name = _cd.get("name", "?")
                                _vuln_basis = (
                                    str(_cd.get("vuln_basis", "")).lower().strip()
                                )
                                if _next_idx >= len(_steps):
                                    _cd["status"] = "completed"
                                    _cd["current_step_index"] = _next_idx
                                    logger.info(
                                        "Exploit chain '%s' COMPLETED after %d steps",
                                        _chain_name,
                                        len(_steps),
                                    )

                                    if _vuln_basis and self.state.hypothesis_queue:
                                        _vb_words = {
                                            w
                                            for w in _vuln_basis.split()
                                            if len(w) >= 4
                                        }
                                        for _hyp in self.state.hypothesis_queue:
                                            if _hyp.get("status") not in (
                                                "pending",
                                                "testing",
                                            ):
                                                continue
                                            _hwords = set(
                                                str(_hyp.get("claim", ""))
                                                .lower()
                                                .split()
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

                                    if _vuln_basis and self.state.hypothesis_queue:
                                        _vb_words = {
                                            w
                                            for w in _vuln_basis.split()
                                            if len(w) >= 4
                                        }
                                        for _hyp in self.state.hypothesis_queue:
                                            if _hyp.get("status") != "pending":
                                                continue
                                            _hwords = set(
                                                str(_hyp.get("claim", ""))
                                                .lower()
                                                .split()
                                            )
                                            if _vb_words & _hwords:
                                                self.state.update_hypothesis(
                                                    str(_hyp.get("id", "")),
                                                    "testing",
                                                    f"Exploit chain '{_chain_name}' in progress (step {_next_idx + 1}/{len(_steps)})",
                                                )
                                                break
                                break
                    except Exception as _chain_adv_e:
                        logger.debug("Chain advancement error: %s", _chain_adv_e)

                    if (
                        success
                        and phase_after_tool.value == "EXPLOIT"
                        and self.state.exploit_chains
                    ):
                        try:
                            _chain_found_match = False
                            _chain_hint_for_correction = ""
                            for _cd in self.state.exploit_chains:
                                if _cd.get("status") not in ("planning", "active"):
                                    continue
                                _cs_idx = int(_cd.get("current_step_index", 0))
                                _steps = _cd.get("steps", [])
                                if _cs_idx >= len(_steps):
                                    continue
                                _cur_step = _steps[_cs_idx]
                                _hint = str(_cur_step.get("tool_hint", "")).lower()
                                _chain_hint_for_correction = _hint

                                if _hint:
                                    _match_token = tool_name.lower()
                                    if _match_token == "execute" and isinstance(  # nosec B105
                                        arguments, dict
                                    ):
                                        _raw_cmd = str(
                                            arguments.get("command", "")
                                        ).strip()
                                        _stripped = re.sub(
                                            r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                                        ).strip()
                                        _binary = (
                                            _stripped.split()[0].lower()
                                            if _stripped
                                            else ""
                                        )
                                        _shell_builtins = {
                                            "cd",
                                            "echo",
                                            "export",
                                            "source",
                                            ".",
                                            "for",
                                            "while",
                                            "if",
                                        }
                                        if _binary and _binary not in _shell_builtins:
                                            _match_token = _binary
                                    if (
                                        _match_token in _hint
                                        or tool_name.lower() in _hint
                                    ):
                                        _chain_found_match = True
                                        break

                            if not _chain_found_match and _chain_hint_for_correction:
                                logger.info(
                                    "Chain correction: LLM used '%s' but chain requires '%s'",
                                    tool_name,
                                    _chain_hint_for_correction,
                                )
                                content_str += (
                                    f"\n\n[EXPLOIT CHAIN CORRECTION] You used '{tool_name}' but your active "
                                    f"exploit chain step requires '{_chain_hint_for_correction}'.\n"
                                    f"USE '{_chain_hint_for_correction}' NOW to advance the chain. "
                                    f"This tool hint is a strong recommendation — ignoring it will waste iterations."
                                )
                        except Exception as _chain_corr_e:
                            logger.debug(
                                "Chain correction injection error: %s", _chain_corr_e
                            )

                self.state.record_tool_use(phase_after_tool.value, tool_name)

                if success:
                    _skip_learning_tools = {
                        "create_file",
                        "read_file",
                        "list_files",
                        "request_user_input",
                    }
                    if tool_name not in _skip_learning_tools:
                        _phase_name = str(phase_after_tool.value).upper()
                        _pattern_type = (
                            "exploit"
                            if _phase_name in {"EXPLOIT", "REPORT"}
                            else "recon"
                        )
                        _technique_name = tool_name
                        _cmd_snapshot = tool_name
                        if tool_name == "execute" and isinstance(arguments, dict):
                            _raw_cmd = str(arguments.get("command", "")).strip()
                            _stripped = re.sub(
                                r"^cd\s+\S+\s*&&\s*", "", _raw_cmd
                            ).strip()
                            if _stripped:
                                _cmd_snapshot = _stripped[:300]
                                _first = (
                                    _stripped.split(maxsplit=1)[0]
                                    .rsplit("/", 1)[-1]
                                    .strip()
                                    .lower()
                                )
                                if _first:
                                    _technique_name = _first
                        self._save_recon_exploit_pattern(
                            technique_name=_technique_name,
                            pattern_type=_pattern_type,
                            commands=[_cmd_snapshot],
                            success=True,
                            description=f"{_phase_name} step using {_technique_name}",
                        )

                budget_note = self._check_tool_budget(tool_name, phase_after_tool.value)
                if budget_note:
                    content_str = budget_note + "\n\n" + content_str

                if (
                    success
                    and tool_name in ("http_observe", "execute")
                    and self._session
                ):
                    _waf_headers: dict[str, str] = result.get("headers", {}) or {}
                    _waf_body: str = str(
                        result.get("body_excerpt") or result.get("stdout") or ""
                    )[:3000]
                    _waf_status: int = int(result.get("status_code") or 0)
                    if _waf_headers or _waf_body:
                        try:
                            _waf_url = arguments.get("url") or arguments.get(
                                "command", ""
                            )
                            try:
                                _waf_host = urlparse(str(_waf_url)).netloc or str(
                                    _waf_url
                                )
                            except Exception as exc:
                                logger.debug("WAF host URL parse error: %s", exc)
                                _waf_host = str(_waf_url)[:50]
                            if not _waf_host or " " in _waf_host:
                                _url_match = re.search(
                                    r"https?://[^\s\"']+", str(_waf_url)
                                )
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
                                    _old_stats = (
                                        _existing.get("strategy_stats", {}) or {}
                                    )

                                if tool_name == "execute" and isinstance(
                                    arguments, dict
                                ):
                                    _cmd_lower = str(
                                        arguments.get("command", "")
                                    ).lower()
                                    _prior_strategies = []
                                    if isinstance(_existing, dict):
                                        _prior_strategies = list(
                                            _existing.get("bypass_strategies", [])
                                        )
                                    _matched_strategy = ""
                                    for _st in _prior_strategies:
                                        _st_l = str(_st).lower()
                                        if "header" in _st_l and any(
                                            h in _cmd_lower
                                            for h in (
                                                "x-forwarded-for",
                                                "user-agent",
                                                "-h ",
                                            )
                                        ):
                                            _matched_strategy = str(_st)
                                            break
                                        if "encoding" in _st_l and (
                                            "%25" in _cmd_lower
                                            or "%2f" in _cmd_lower
                                            or "%27" in _cmd_lower
                                        ):
                                            _matched_strategy = str(_st)
                                            break
                                        if "case variation" in _st_l and any(
                                            k in _cmd_lower
                                            for k in ("union", "select", "script")
                                        ):
                                            _matched_strategy = str(_st)
                                            break
                                        if "verb" in _st_l and any(
                                            m in _cmd_lower
                                            for m in (
                                                "-x post",
                                                "-x put",
                                                "-x patch",
                                                "-x delete",
                                            )
                                        ):
                                            _matched_strategy = str(_st)
                                            break
                                    if _matched_strategy:
                                        _stat = _old_stats.setdefault(
                                            _matched_strategy,
                                            {"attempts": 0, "successes": 0},
                                        )
                                        _stat["attempts"] = (
                                            int(_stat.get("attempts", 0)) + 1
                                        )
                                        if _waf_status and _waf_status not in (
                                            403,
                                            406,
                                            412,
                                            429,
                                            501,
                                            999,
                                        ):
                                            _stat["successes"] = (
                                                int(_stat.get("successes", 0)) + 1
                                            )
                                _ranked = rank_bypass_strategies(_merged, _old_stats)[
                                    :8
                                ]
                                _merged.bypass_strategies = _ranked
                                _history: list[dict[str, Any]] = []
                                if isinstance(_existing, dict) and isinstance(
                                    _existing.get("history"), list
                                ):
                                    _history = list(_existing["history"])
                                _history.append(
                                    {
                                        "iteration": self.state.iteration,
                                        "status_code": _waf_status,
                                        "tool": tool_name,
                                        "confidence": round(_merged.confidence, 3),
                                        "waf_name": _merged.waf_name,
                                    }
                                )
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
                                    self.state.conversation = [
                                        m
                                        for m in self.state.conversation
                                        if not m.get("content", "").startswith(
                                            f'<waf_bypass host="{_waf_host}"'
                                        )
                                    ]
                                    self.state.conversation.append(
                                        {
                                            "role": "system",
                                            "content": _waf_ctx,
                                        }
                                    )
                                    logger.info(
                                        "WAF detected on %s: %s (conf=%.0f%%)",
                                        _waf_host,
                                        _merged.waf_name,
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
                    if self.state.planned_tools:
                        executed_tools = set()
                        for hist in self.state.tool_history:
                            executed_tools.add(hist.tool_name)

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
                self._append_tool_result(tool_name, content_str, success, tc.get("id"))

                self._mentor_tool_call_count += 1

            self._refresh_exploration_state()

            maybe_inject_mentor_analysis(
                self,
                current_phase=current_phase,
                all_results=all_results,
            )

            if self._session:
                save_session(self._session)

            if has_task_complete:
                logger.info("Agent emitted [TASK_COMPLETE] after tools — stopping.")
                self._iteration_terminated = True
                yield AgentEvent(type="done", data={})
                return
