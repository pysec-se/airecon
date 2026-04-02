from __future__ import annotations

import json
import logging
import re
import warnings
from pathlib import Path
from typing import Any

from ..system import auto_load_skills_for_message
from .pipeline import PipelinePhase

logger = logging.getLogger("airecon.agent")

_tools_meta_path = Path(__file__).parent.parent / "data" / "tools_meta.json"
try:
    with open(_tools_meta_path, "r") as f:
        _TOOLS_META = json.load(f)
except (OSError, json.JSONDecodeError) as _e:
    warnings.warn(f"tools_meta.json unavailable ({_e}); tool catalog features disabled.")
    _TOOLS_META = {}


class _CycleLlmMixin:
    def _analyze_llm_output(
        self,
        current_phase: Any,
        content_acc: str,
        thinking_acc: str,
        tool_calls_acc: list[dict[str, Any]],
    ) -> tuple[str, str, list[dict[str, Any]], bool]:
            combined_response = content_acc + " " + thinking_acc

            hallucination_signals = [
                "i have found",
                "the scan shows",
                "the results indicate",
                "my analysis shows",
                "it appears that",
                "based on my knowledge",
                "without running",
                "i don't have access to",
                "i will run",
                "let me run",
                "let me execute",
                "i'll run",
                "i'll execute",
                "i would run",
                "next, i'll",
                "i should run",
            ]
            combined_lower = combined_response.lower()
            has_hallucination_risk = any(
                signal in combined_lower for signal in hallucination_signals
            )

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

            _in_active_session = bool(self.state.active_target)
            _nudge_threshold_met = (
                is_post_vuln_context
                or (_in_active_session and self._no_tool_iterations >= 1)
                or self._no_tool_iterations >= 2
            )
            if (has_hallucination_risk or has_fake_cmd_block) and not tool_calls_acc:
                if has_fake_cmd_block:

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
                    content_acc = ""
                elif is_post_vuln_context:

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

            _text_only_threshold = 1 if _in_active_session else 2
            if not tool_calls_acc and content_acc.strip() and self._no_tool_iterations >= _text_only_threshold:

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

                    tool_calls_acc = []
                    content_acc = ""

            _has_task_complete = "[TASK_COMPLETE]" in content_acc
            content_acc = content_acc.replace(
                "[TASK_COMPLETE]", "").strip()

            if "<objective_patch" in content_acc:
                self._apply_objective_patch(content_acc, current_phase)
                content_acc = self._OBJECTIVE_PATCH_RE.sub(
                    "", content_acc
                ).strip()

            self.state.add_message(
                "assistant", content_acc, tool_calls_acc, thinking_acc
            )

            if self._session and content_acc:

                hedge_words = [
                    "might", "could", "possibly", "appears", "suggests",
                    "may", "potentially", "likely", "probable", "seems",
                ]
                is_confident = not any(hedge in content_acc.lower() for hedge in hedge_words)

                if is_confident:

                    vuln_claim_patterns = [
                        r"(sql\s*(injection)?|xss|ssrf|idor|rce|lfi|rfi|xxe|command\s+injection)\s+(in|at|on|found\s+in|detected\s+at)\s+([^\s,.!?]+)",
                    ]
                    for pattern in vuln_claim_patterns:
                        matches = re.findall(pattern, content_acc.lower())
                        for match in matches:

                            if isinstance(match, tuple) and len(match) >= 4:
                                vuln_type = match[0].strip()
                                endpoint = match[3].strip()
                                claim_text = f"{vuln_type} in {endpoint}"
                            else:
                                continue

                            has_session_evidence = False
                            if self._session.vulnerabilities:
                                has_session_evidence = any(
                                    vuln_type in " ".join([
                                        str(v.get("finding", "")),
                                        str(v.get("title", "")),
                                        str(v.get("evidence", "")),
                                        str(v.get("proof", "")),
                                    ]).lower()
                                    and endpoint in " ".join([
                                        str(v.get("finding", "")),
                                        str(v.get("title", "")),
                                        str(v.get("evidence", "")),
                                        str(v.get("proof", "")),
                                    ]).lower()
                                    for v in self._session.vulnerabilities
                                )

                            has_tool_evidence = False
                            vuln_scanner_tools = {"sqlmap", "nuclei", "ffuf", "katana", "execute"}
                            for tc in tool_calls_acc:
                                tc_name = tc.get("function", {}).get("name", "")
                                tc_args = tc.get("function", {}).get("arguments", {})
                                if tc_name in vuln_scanner_tools:

                                    tc_url = str(tc_args.get("url", tc_args.get("command", ""))).lower()
                                    if endpoint.lower() in tc_url:
                                        has_tool_evidence = True
                                        break

                            if not has_session_evidence and not has_tool_evidence:
                                logger.warning(
                                    "HALLUCINATION DETECTED: Claimed '%s' but no tool called and no session evidence",
                                    claim_text,
                                )

                                self.state.conversation.append({
                                    "role": "system",
                                    "content": (
                                        f"[SYSTEM: HALLUCINATION WARNING] You claimed '{claim_text}' "
                                        f"but no scanner tool (sqlmap/nuclei/ffuf) was called for this endpoint "
                                        f"and it's not in confirmed vulnerabilities. "
                                        f"Either: (1) call the appropriate scanner tool first, "
                                        f"(2) use hedged language ('might be', 'appears to'), or "
                                        f"(3) provide the tool output that confirms this finding."
                                    ),
                                })

            _llm_output_for_skills = (
                content_acc + " " + thinking_acc).strip()
            if _llm_output_for_skills:

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

                    if self._session:
                        for skill_rel in _new_loaded_skills:
                            if skill_rel not in self._session.loaded_skills:
                                self._session.loaded_skills.append(skill_rel)

                if _new_skill_ctx:

                    _skill_key = hash(_new_skill_ctx[:200])
                    if _skill_key not in self._loaded_skill_hashes:
                        self._loaded_skill_hashes.add(_skill_key)

                        self.state.conversation.append(
                            {"role": "system", "content": _new_skill_ctx, "iteration": self.state.iteration}
                        )
                        logger.debug(
                            "Auto-loaded skill from LLM output keywords"
                        )

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


            return content_acc, thinking_acc, tool_calls_acc, _has_task_complete
