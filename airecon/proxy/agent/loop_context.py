"""Context management, compression, and building helpers for AgentLoop.

Extracted from loop.py to keep that file manageable. Contains:
- _MAX_TOOL_RESULT_CHARS — per-message tool result character cap
- _inject_exploit_vuln_context — pin confirmed vulns at EXPLOIT phase start
- _compact_phase_context — compress old phase tool outputs on phase transition
- _messages_for_ollama — strip thinking from all-but-last assistant message
- _get_tool_result_cap / _cap_tool_result — scale and apply per-msg result cap
- _call_compression_llm — AIRecon-style iterative LLM summary before truncation
- _enforce_char_budget — async pre-call guard: compress if chars exceed budget
- _append_tool_result — add tool result to conversation with cap + role handling
- _build_critical_findings_context — pin critical findings before truncation
- _build_compressed_findings_summary — dense pinned summary every 20 iters
- _build_handoff_summary — structured AIRecon-style task-progress summary
- _compress_old_tool_outputs — replace old verbose tool outputs with 1-line stubs
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from ..config import get_config
from .models import AgentState
from .session import get_untested_injection_points

logger = logging.getLogger("airecon.agent")


class _ContextMixin:
    """Mixin: context window management, compression, and structured building."""

    # Hard per-message character cap for tool results.
    # Prevents a single large tool output from consuming the entire context.
    _MAX_TOOL_RESULT_CHARS: int = 15_000

    def _inject_exploit_vuln_context(self) -> None:
        """Inject a pinned vulnerability summary at the start of EXPLOIT phase.

        Ensures the model has direct, unambiguous access to ALL confirmed
        vulnerabilities from ANALYSIS — preventing loss of critical targets due
        to context truncation. This message is prepended using the
        protected_system bucket so it survives _enforce_char_budget().
        """
        if not self._session:
            return

        vulns = self._session.vulnerabilities or []
        injection_pts = self._session.injection_points or []

        if not vulns and not injection_pts:
            return

        lines = [
            "[SYSTEM: EXPLOIT PHASE — CONFIRMED ATTACK SURFACE]",
            "Exploit each item below systematically. Do NOT re-discover — go straight to exploitation.\n",
        ]

        if vulns:
            lines.append("## Confirmed Vulnerabilities:")
            for i, v in enumerate(vulns[:25], 1):
                finding = str(
                    v.get("finding")
                    or v.get("title")
                    or v.get("name")
                    or "Unknown finding"
                )
                url = str(
                    v.get("url")
                    or v.get("endpoint")
                    or v.get("evidence")
                    or v.get("proof")
                    or ""
                )
                sev_raw = str(v.get("severity", "")).strip()
                if sev_raw in {"5", "4", "3", "2", "1"}:
                    sev = {"5": "CRITICAL", "4": "HIGH", "3": "MEDIUM", "2": "LOW", "1": "INFO"}[sev_raw]
                else:
                    sev = sev_raw
                if not sev:
                    f_up = finding.upper()
                    for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                        if f"[{lbl}]" in f_up or f"{lbl}:" in f_up:
                            sev = lbl
                            break
                param = v.get("parameter", "")
                detail = f" (param: {param})" if param else ""
                lines.append(f"  {i}. [{sev}] {finding}{detail} — {url}")

        if injection_pts:
            lines.append("\n## Injection Points — test each by its type:")
            for j, ip in enumerate(injection_pts[:20], 1):
                url = ip.get("url", "")
                param = ip.get("parameter", "")
                method = ip.get("method", "GET")
                itype = ip.get("type_hint", "INJECT")
                lines.append(f"  {j}. [{itype}] {method} {url} param={param}")

        lines.append(
            "\nPriority order: CRITICAL > HIGH > MEDIUM. "
            "Confirm each exploit with proof-of-concept output showing actual impact."
        )

        vuln_ctx = "\n".join(lines)
        self.state.conversation.append({
            "role": "system",
            "content": vuln_ctx,
            "_bucket": "protected_system",
        })

    def _compact_phase_context(self, from_phase: str) -> None:
        """Compress raw tool results from a completed phase to free KV cache space.

        When transitioning (e.g. RECON→ANALYSIS), the bulk of old raw tool
        outputs (full nmap/subfinder/httpx dumps) is no longer needed verbatim.
        We keep the last 15 messages intact and collapse old tool output to
        short stubs, reclaiming tens of thousands of context tokens.

        Findings (vulnerabilities, structured data) are never touched — they
        live in session state (self._session), not as raw conversation messages.
        """
        msgs = self.state.conversation
        keep_recent = 15
        cutoff = max(0, len(msgs) - keep_recent)
        compacted_tools = 0
        compacted_thinking = 0
        chars_freed = 0

        for i, msg in enumerate(msgs[:cutoff]):
            role = msg.get("role")
            content = str(msg.get("content", ""))

            if role == "tool" and len(content) > 400:
                stub = content[:200].rstrip()
                freed = len(content) - len(stub)
                msg["content"] = (
                    stub
                    + f" ...[{from_phase} phase output compacted — {freed} chars freed]"
                )
                chars_freed += freed
                compacted_tools += 1

            elif role == "assistant" and msg.get("thinking"):
                thinking_len = len(str(msg["thinking"]))
                msg.pop("thinking", None)
                chars_freed += thinking_len
                compacted_thinking += 1

        if compacted_tools or compacted_thinking:
            logger.info(
                "Phase transition compaction (%s→next): %d tool msgs, "
                "%d thinking strips, ~%d chars freed",
                from_phase, compacted_tools, compacted_thinking, chars_freed,
            )

    def _messages_for_ollama(self) -> list[dict[str, Any]]:
        """Return a view of the conversation with thinking stripped from old messages.

        Thinking traces from previous iterations are already encoded in their
        corresponding content/tool_calls and provide no additional value when
        replayed to Ollama — they only consume KV cache tokens.

        Strategy: keep thinking only in the LAST assistant message (most recent turn).
        This recovers 50-200K tokens in long sessions without losing any information.
        _enforce_char_budget() handles the stateful strip when budget is exceeded;
        this method handles the API-call view for every iteration.
        """
        msgs = self.state.conversation
        last_assistant_idx = -1
        for i, m in enumerate(msgs):
            if m.get("role") == "assistant":
                last_assistant_idx = i

        if last_assistant_idx == -1:
            return list(msgs)

        result = []
        for i, msg in enumerate(msgs):
            if (
                msg.get("role") == "assistant"
                and i != last_assistant_idx
                and msg.get("thinking")
            ):
                msg = {k: v for k, v in msg.items() if k != "thinking"}
            result.append(msg)
        return result

    def _get_tool_result_cap(self) -> int:
        """Return per-message tool result cap scaled to current context window."""
        # CTF mode: hard cap at 1500 chars — each tool result must be tiny so
        # the rolling conversation window can hold 15-20 results without overflow.
        if self._ctf_mode:
            return 1500
        ctx = self._adaptive_num_ctx if self._adaptive_num_ctx > 0 else get_config().ollama_num_ctx
        # 8% of estimated token budget in chars (1 token ≈ 3 chars)
        # With 128K ctx: 128000 * 0.08 * 3 = ~30K → capped at 15K
        cap = max(3_000, min(self._MAX_TOOL_RESULT_CHARS, int(ctx * 0.08 * 3)))
        return cap

    def _cap_tool_result(self, content: str) -> str:
        """Truncate a large tool result before adding it to conversation.

        Keeps the first 70 % and last 10 % of the content so that both the
        command summary and the tail (often a final summary/stats line) are
        preserved.  Cap scales down when VRAM-crash mode is active.
        """
        cap = self._get_tool_result_cap()
        if len(content) <= cap:
            return content
        head = int(cap * 0.70)
        tail = int(cap * 0.10)
        omitted = len(content) - head - tail
        return (
            content[:head]
            + f"\n...[{omitted} chars omitted]...\n"
            + content[-tail:]
        )

    async def _call_compression_llm(
        self,
        messages_to_compress: list[dict[str, Any]],
    ) -> str:
        """Generate an iterative AIRecon-style summary of messages about to be dropped.

        On first call (self._compression_summary is empty): produces a structured
        summary (Goal / Progress / Key Findings / Key Decisions / Next Steps).

        On subsequent calls: passes the prior summary and asks the model to
        PRESERVE still-relevant content and ADD new context — this is the core
        AIRecon iterative-update pattern that prevents knowledge loss across
        multiple compression cycles.

        Uses self.ollama.complete() — the lightweight non-streaming path already
        designed for "internal use (e.g. memory compression)" — with a small
        num_predict budget (1500 tokens) and low temperature (0.1) to keep it
        fast and deterministic.

        Returns the summary string, or "" if the call fails or is skipped
        (caller will fall back to destructive Pass-2 truncation).
        """
        if not messages_to_compress:
            return ""
        if not getattr(self, "ollama", None):
            return ""
        # Skip during VRAM crash recovery — an extra LLM call risks re-triggering OOM.
        if self._recovery_force_tool_calls > 0:
            return ""

        # Build compact text of messages to compress (capped per-message).
        _PER_MSG_CAP = 350
        chunks: list[str] = []
        for msg in messages_to_compress:
            role = msg.get("role", "?")
            content = str(msg.get("content", ""))[:_PER_MSG_CAP].strip()
            if not content:
                continue
            chunks.append(f"[{role.upper()}] {content}")

        if not chunks:
            return ""

        messages_text = "\n\n".join(chunks)
        prior = self._compression_summary  # type: ignore[attr-defined]  # set in AgentLoop.__init__

        if prior:
            system_content = (
                "You are a context compression assistant for a security assessment agent.\n"
                "Update the existing summary with new information from the messages below.\n"
                "PRESERVE everything still relevant from the previous summary.\n"
                "ADD new findings, progress, and decisions from the new messages.\n"
                "Always keep: flags, CVEs, credentials, confirmed vulnerabilities, endpoints."
            )
            user_content = (
                f"## Previous Summary (PRESERVE relevant parts):\n{prior}\n\n"
                f"## New Messages to Integrate:\n{messages_text}\n\n"
                "Output an updated structured summary:\n"
                "## Goal\n## Progress\n### Done\n### In Progress\n"
                "## Key Findings\n## Key Decisions\n## Next Steps"
            )
        else:
            system_content = (
                "You are a context compression assistant for a security assessment agent.\n"
                "Summarize the conversation messages below into a structured handoff.\n"
                "Keep ALL security findings: flags, CVEs, credentials, endpoints, vulnerabilities."
            )
            user_content = (
                f"## Messages to Summarize:\n{messages_text}\n\n"
                "Output a structured summary:\n"
                "## Goal\n## Progress\n### Done\n### In Progress\n"
                "## Key Findings\n## Key Decisions\n## Next Steps"
            )

        try:
            summary = await self.ollama.complete(  # type: ignore[attr-defined]
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content},
                ],
                options={"num_predict": 1500, "temperature": 0.1},
            )
            return summary.strip()
        except Exception as exc:
            logger.warning(
                "Iterative compression LLM call failed: %s — falling back to truncation", exc
            )
            return ""

    async def _enforce_char_budget(
        self, num_ctx: int, num_predict: int | None = None
    ) -> None:
        """Hard pre-call guard: compress conversation if total chars exceed token budget.

        Runs before every Ollama call. Prevents OOM from large tool outputs
        accumulating across iterations even after message-count truncation.

        Ollama's num_ctx is the TOTAL KV cache for both input AND output tokens.
        The effective input budget = num_ctx - num_predict. Using the full num_ctx
        as the budget causes silent context truncation by Ollama when the input
        exceeds (num_ctx - num_predict), stripping the system prompt and causing
        hallucination. We subtract the output reservation to trigger compression
        before Ollama does its own (destructive) truncation.

        Budget = (num_ctx - num_predict) * 3 chars (1 token ≈ 3 chars).
        At 128K ctx / 32K predict: (131072-32768)*3 = ~294K chars input budget.
        """
        cfg = get_config()
        effective_predict = (
            self._fit_num_predict_to_ctx(num_predict, num_ctx)
            if num_predict is not None
            else self._fit_num_predict_to_ctx(
                getattr(cfg, "ollama_num_predict", 32768), num_ctx
            )
        )
        # Reserve tokens for tool definitions sent in the API call.
        # With 20 tools × ~250 tokens avg = ~5000 tokens not visible in
        # conversation messages but counted by Ollama toward the KV cache.
        _tools_count = len(self._tools_ollama) if self._tools_ollama is not None else 20
        _tools_overhead = _tools_count * 250
        effective_input_ctx = max(1024, num_ctx - effective_predict - _tools_overhead)
        budget = effective_input_ctx * 3
        total = sum(
            len(str(m.get("content") or ""))
            + len(str(m.get("tool_calls") or ""))
            + len(str(m.get("thinking") or ""))   # thinking traces count toward budget
            for m in self.state.conversation
        )
        if total <= budget:
            return

        logger.warning(
            "Pre-call char budget exceeded: %d chars > %d budget (num_ctx=%d) — compressing",
            total, budget, num_ctx,
        )

        # Pass 0: strip thinking from ALL assistant messages except the most recent 3.
        # Thinking traces accumulate rapidly (1500+ tokens each) and are invisible to
        # the old total calculation, silently overflowing the context window and causing
        # Ollama to truncate the system prompt → hallucination / scope loss.
        # The thinking is already captured in content/tool_calls — safe to drop from history.
        assistant_indices = [
            i for i, m in enumerate(self.state.conversation)
            if m.get("role") == "assistant" and m.get("thinking")
        ]
        # Keep thinking only in the most recent 3 assistant turns
        for idx in assistant_indices[:-3]:
            thinking_len = len(str(self.state.conversation[idx].get("thinking", "")))
            self.state.conversation[idx].pop("thinking", None)
            total -= thinking_len
            if total <= budget:
                logger.info("Budget restored after thinking strip (%d msgs)", len(assistant_indices))
                return

        # Pass 1: compress tool/user messages over compress_cap chars.
        # EXCEPTION: the first user message contains the original task/scope instruction
        # (e.g. "pentest target.com"). Never compress it — trimming it causes scope loss
        # and out-of-scope behavior on the next LLM call.
        compress_cap = max(300, budget // max(1, len(self.state.conversation)))
        first_user_seen = False
        for msg in self.state.conversation:
            role = msg.get("role")
            if role == "user" and not first_user_seen:
                first_user_seen = True
                continue  # protect original task message
            if role in ("tool", "user"):
                content = str(msg.get("content", ""))
                if len(content) > compress_cap:
                    msg["content"] = content[:compress_cap] + f"...[hard-trimmed {len(content)} chars]"

        # Recheck after pass 1
        total = sum(
            len(str(m.get("content") or ""))
            + len(str(m.get("thinking") or ""))
            for m in self.state.conversation
        )
        if total <= budget:
            return

        # iterative LLM compression.
        # Before dropping messages destructively (Pass 2), try to summarise the
        # oldest non-system messages and inject the result as a pinned
        # [SYSTEM: COMPRESSION SUMMARY] message.  This preserves key findings
        # (flags, CVEs, endpoints, credentials) that would otherwise be silently
        # lost.  On re-compression the prior summary is passed to the model so it
        # can PRESERVE still-relevant content and ADD new context — avoiding the
        # knowledge-decay that plagues naive truncation schemes.
        # If the LLM call fails for any reason, we fall through to Pass 2.
        _non_system = [m for m in self.state.conversation if m.get("role") != "system"]
        _keep_recent_non_sys = 15  # always preserve the most recent 15 non-system turns
        _candidates = _non_system[:max(0, len(_non_system) - _keep_recent_non_sys)]
        if len(_candidates) >= 5:
            _summary = await self._call_compression_llm(_candidates)
            if _summary:
                self._compression_summary = _summary  # type: ignore[attr-defined]
                # Remove any previous compression summary to avoid accumulation.
                self.state.conversation = [
                    m for m in self.state.conversation
                    if not str(m.get("content", "")).startswith("[SYSTEM: COMPRESSION SUMMARY")
                ]
                # Inject pinned summary right before the first non-system message
                # so it lands in core_system and survives all future truncations.
                _first_non_sys_idx = next(
                    (i for i, m in enumerate(self.state.conversation)
                     if m.get("role") != "system"),
                    len(self.state.conversation),
                )
                self.state.conversation.insert(
                    _first_non_sys_idx,
                    {
                        "role": "system",
                        "content": f"[SYSTEM: COMPRESSION SUMMARY]\n{_summary}",
                    },
                )
                logger.info(
                    "Iterative compression: %d messages summarised → %d chars pinned",
                    len(_candidates), len(_summary),
                )
                # Recheck — Pass 2 may still be needed if summary alone didn't free enough.
                total = sum(
                    len(str(m.get("content") or "")) + len(str(m.get("thinking") or ""))
                    for m in self.state.conversation
                )
                if total <= budget:
                    return

        # Pass 2: drop oldest non-critical messages until we fit.
        # CTF mode: drop aggressively to 8 messages — the agent needs a clean
        # window more than it needs full history. Normal: drop to half.
        # When Pass 1.5 succeeded, the dropped messages are already summarised
        # in the pinned [SYSTEM: COMPRESSION SUMMARY] message above.
        _min_msgs = 8 if self._ctf_mode else 15
        target_msgs = max(_min_msgs, len(self.state.conversation) // (3 if self._ctf_mode else 2))
        self.state.truncate_conversation(max_messages=target_msgs)
        logger.warning(
            "Pre-call char budget: after truncation → %d messages",
            len(self.state.conversation),
        )

    def _append_tool_result(
        self,
        tool_name: str,
        content_str: str,
        success: bool,
        tool_call_id: str | None = None,
    ) -> None:
        cfg = get_config()
        content_str = self._cap_tool_result(content_str)
        if cfg.tool_response_role.lower() == "tool":
            tool_msg: dict[str, Any] = {
                "role": "tool",
                "name": tool_name,
                "content": content_str,
            }
            if tool_call_id:
                tool_msg["tool_call_id"] = tool_call_id
            self.state.conversation.append(tool_msg)
        else:
            status = "successfully" if success else "with errors"
            self.state.conversation.append(
                {
                    "role": "user",
                    "content": f"[SYSTEM: Tool '{tool_name}' executed {status}]\nOutput:\n{content_str}",
                }
            )

    def _build_critical_findings_context(self) -> str:
        """Build critical findings context to pin before truncation."""
        if not self._session:
            return ""

        s = self._session
        parts = ["[SYSTEM: CRITICAL FINDINGS — DO NOT LOSE]"]

        if s.subdomains:
            parts.append(
                f"SUBDOMAINS ({len(s.subdomains)}): {', '.join(s.subdomains[:20])}"
            )
            if len(s.subdomains) > 20:
                parts.append(f"... and {len(s.subdomains) - 20} more")

        if s.live_hosts:
            parts.append(
                f"LIVE HOSTS ({len(s.live_hosts)}): {', '.join(s.live_hosts[:15])}"
            )
        elif s.subdomains:
            # Subdomains found but no live_hosts yet — warn the LLM to validate first
            parts.append(
                "WARNING: subdomains enumerated but NOT YET validated. "
                "Run: httpx -l output/subdomains.txt -sc -o output/live_hosts.txt "
                "to filter live hosts BEFORE port scanning or directory brute-force."
            )

        if s.open_ports:
            port_summary = []
            for host, ports in list(s.open_ports.items())[:10]:
                port_summary.append(f"{host}:{','.join(map(str, ports[:5]))}")
            parts.append(f"OPEN PORTS: {'; '.join(port_summary)}")

        if s.urls:
            parts.append(f"URLs ({len(s.urls)}): {', '.join(s.urls[:10])}")

        if s.vulnerabilities:
            vuln_vals = []
            for v in s.vulnerabilities[:10]:
                vt = v.get("title", v.get("finding", "Unknown"))
                vf = v.get("flag")
                if vf:
                    vuln_vals.append(f"{vt} (FLAG: {vf})")
                else:
                    vuln_vals.append(vt)
            parts.append(f"VULNERABILITIES: {'; '.join(vuln_vals)}")

        # Injection points: show untested first so they don't get lost after
        # context truncation — these are the highest-priority attack surface.
        if s.injection_points:
            untested = get_untested_injection_points(s)
            all_ips = s.injection_points
            tested_count = len(all_ips) - len(untested)
            # Show up to 8 untested injection points; fallback to all if none untested
            show = untested[:8] if untested else all_ips[:8]
            ip_lines: list[str] = []
            for pt in show:
                path = urlparse(pt.get("url", "")).path or pt.get("url", "")
                ip_lines.append(
                    f"  [{pt.get('type_hint','?')}] {pt.get('parameter','?')} @ {path}"
                )
            untested_note = f"{len(untested)} UNTESTED" if untested else "all tested"
            parts.append(
                f"INJECTION POINTS ({len(all_ips)} total, {untested_note}, {tested_count} tested):\n"
                + "\n".join(ip_lines)
                + (f"\n  ... +{len(untested) - 8} more untested" if len(untested) > 8 else "")
            )

        if s.technologies:
            tech_parts = [
                f"{name}/{ver}" if ver else name
                for name, ver in list(s.technologies.items())[:10]
            ]
            parts.append(f"TECHNOLOGIES: {', '.join(tech_parts)}")

        if s.completed_phases:
            parts.append(f"COMPLETED PHASES: {', '.join(s.completed_phases)}")

        if s.tested_endpoints:
            # Show last 20 tested endpoints so the LLM knows what NOT to repeat
            shown = s.tested_endpoints[-20:]
            remainder = len(s.tested_endpoints) - len(shown)
            ep_note = (
                f"... and {remainder} more already tested" if remainder > 0 else ""
            )
            parts.append(
                f"ALREADY TESTED ENDPOINTS ({len(s.tested_endpoints)} total"
                + (", showing last 20" if remainder > 0 else "")
                + "):\n"
                + "\n".join(f"  {ep}" for ep in shown)
                + (f"\n  {ep_note}" if ep_note else "")
            )

        return "\n".join(parts)

    def _build_compressed_findings_summary(self) -> str:
        """Build a dense pinned summary of confirmed findings so far.

        This is injected as [SYSTEM: PINNED CONTEXT] before truncation every
        20 iterations. It ensures the LLM never forgets high-value discoveries
        even as old messages are dropped.

        Contents: confirmed vulns, credentials, active hypotheses, untested IPs.
        """
        if not self._session and not self.state.hypothesis_queue and not self.state.evidence_log:
            return ""

        parts: list[str] = ["[SYSTEM: PINNED CONTEXT — confirmed findings, hypotheses, gaps]"]
        added_any = False

        # Confirmed vulnerabilities
        if self._session and self._session.vulnerabilities:
            vulns = self._session.vulnerabilities[:10]
            vlines = [f"  - {v.get('finding', '')[:120]}" for v in vulns]
            parts.append(f"CONFIRMED VULNS ({len(self._session.vulnerabilities)}):")
            parts.extend(vlines)
            added_any = True

        # Active (pending/testing) hypotheses
        pending_hyps = self.state.get_pending_hypotheses(max_items=5)
        if pending_hyps:
            parts.append("ACTIVE HYPOTHESES TO TEST:")
            for h in pending_hyps:
                parts.append(f"  [{h.get('id','')}] {h.get('claim','')[:100]}")
                if h.get("test_plan"):
                    parts.append(f"    → {h.get('test_plan','')[:80]}")
            added_any = True

        # High-confidence evidence from this phase
        if self.state.evidence_log:
            high_ev = [
                e for e in self.state.evidence_log
                if int(e.get("severity", 1)) >= 4
                and float(e.get("confidence", 0.0)) >= 0.75
            ][-5:]
            if high_ev:
                parts.append("HIGH-VALUE EVIDENCE:")
                for ev in high_ev:
                    parts.append(
                        f"  [{ev.get('source_tool','tool')}][SEV={ev.get('severity',1)}] "
                        f"{ev.get('summary','')[:120]}"
                    )
                added_any = True

        if not added_any:
            return ""

        return "\n".join(parts)

    def _build_handoff_summary(self) -> str:
        """Build a structured task-progress summary context_compressor.

        uses LLM-generated summaries (Goal / Progress / Key Decisions /
        Relevant Files / Next Steps). AIRecon uses a static build from structured
        session state — faster, local-only, no extra LLM call.

        This is injected alongside _build_critical_findings_context() during
        proactive context trim so the LLM is always oriented after truncation.
        """
        lines: list[str] = ["[SYSTEM: HANDOFF SUMMARY — task progress & orientation]"]

        # --- Goal: original user request (first user message) ---
        original_task = ""
        for msg in self.state.conversation:
            if msg.get("role") == "user":
                original_task = str(msg.get("content", ""))[:300]
                break
        if original_task:
            lines.append(f"## Goal\n{original_task}")

        # --- Progress: Done / In Progress ---
        done_lines: list[str] = []
        if self._session and self._session.completed_phases:
            done_lines.append(f"Phases completed: {', '.join(self._session.completed_phases)}")
        if self._session and self._session.subdomains:
            done_lines.append(f"Subdomains enumerated: {len(self._session.subdomains)}")
        if self._session and self._session.live_hosts:
            done_lines.append(f"Live hosts confirmed: {len(self._session.live_hosts)}")
        if self._session and self._session.vulnerabilities:
            done_lines.append(
                f"Vulnerabilities confirmed: {len(self._session.vulnerabilities)} "
                f"({', '.join(v.get('finding','')[:50] for v in self._session.vulnerabilities[:3])})"
            )
        if self._session and self._session.tested_endpoints:
            done_lines.append(f"Endpoints tested: {len(self._session.tested_endpoints)}")

        current_phase_str = "UNKNOWN"
        if self.pipeline:
            try:
                current_phase_str = self.pipeline.get_current_phase().value
            except Exception:
                pass

        in_progress_lines: list[str] = [f"Current phase: {current_phase_str}"]

        # Active objectives as "In Progress"
        active_objs = [
            o for o in (self.state.objective_queue or [])
            if o.get("status") == "pending"
        ][:3]
        for obj in active_objs:
            obj_text = str(obj.get("title") or obj.get("description") or "").strip()
            if obj_text:
                in_progress_lines.append(f"  → {obj_text[:100]}")

        # Active hypotheses
        pending_hyps = self.state.get_pending_hypotheses(max_items=3)
        for h in pending_hyps:
            in_progress_lines.append(f"  [hypothesis] {h.get('claim','')[:80]}")

        if done_lines or in_progress_lines:
            lines.append("## Progress")
            if done_lines:
                lines.append("### Done")
                lines.extend(f"  - {line}" for line in done_lines)
            if in_progress_lines:
                lines.append("### In Progress")
                lines.extend(f"  - {line}" for line in in_progress_lines)

        # --- Key Decisions: technologies, attack surface ---
        decision_lines: list[str] = []
        if self._session and self._session.technologies:
            tech = ", ".join(
                f"{k}/{v}" if v else k
                for k, v in list(self._session.technologies.items())[:6]
            )
            decision_lines.append(f"Technology stack: {tech}")
        if self._session and self._session.waf_profiles:
            for host, wp in list(self._session.waf_profiles.items())[:2]:
                decision_lines.append(
                    f"WAF detected on {host}: {wp.get('waf_name','?')} "
                    f"(confidence={wp.get('confidence',0):.0%})"
                )
        if decision_lines:
            lines.append("## Key Context")
            lines.extend(f"  - {line}" for line in decision_lines)

        # --- Next Steps: untested injection points ---
        if self._session and self._session.injection_points:
            untested = get_untested_injection_points(self._session)[:5]
            if untested:
                lines.append("## Next Steps")
                lines.append("  Untested injection points remaining:")
                for pt in untested:
                    path = urlparse(pt.get("url", "")).path or pt.get("url", "")
                    lines.append(
                        f"    [{pt.get('type_hint','?')}] "
                        f"{pt.get('parameter','?')} @ {path}"
                    )

        if len(lines) <= 1:
            return ""  # Only header, nothing useful
        return "\n".join(lines)

    def _compress_old_tool_outputs(self) -> None:
        """Replace verbose tool outputs older than 20 messages with 1-line summaries.

        Called every 20 iterations. Preserves key info (URLs, errors, statuses)
        via AgentState._extract_key_info() while reducing context token usage.
        Only compresses messages outside the most-recent 20 to avoid touching
        in-progress context the LLM currently depends on.
        """
        non_system = [m for m in self.state.conversation if m.get("role") != "system"]
        if len(non_system) <= 20:
            return  # Not enough messages to compress

        compress_count = 0
        # Compress tool results older than the last 20 non-system messages
        boundary_ids = set(id(m) for m in non_system[-20:])

        for msg in self.state.conversation:
            if id(msg) in boundary_ids:
                continue
            role = msg.get("role", "")
            content = str(msg.get("content", ""))

            if role == "tool" and len(content) > 300 and not content.startswith("[COMPRESSED]"):
                key_info = AgentState._extract_key_info(content, max_chars=200)
                msg["content"] = f"[COMPRESSED] {key_info.strip()}"
                compress_count += 1

        if compress_count:
            logger.debug(
                "Compressed %d old tool outputs at iteration %d",
                compress_count, self.state.iteration,
            )
