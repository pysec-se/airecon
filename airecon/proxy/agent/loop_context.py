from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from ..config import get_config
from .models import AgentState
from .session import get_untested_injection_points

logger = logging.getLogger("airecon.agent")

class _ContextMixin:
    _MAX_TOOL_RESULT_CHARS: int = 15_000

    def _inject_exploit_vuln_context(self) -> None:
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
        if self._ctf_mode:
            return 1500
        ctx = self._adaptive_num_ctx if self._adaptive_num_ctx > 0 else get_config().ollama_num_ctx

        base_cap = max(3_000, min(self._MAX_TOOL_RESULT_CHARS, int(ctx * 0.08 * 3)))

        used = self.state.token_usage.get("used", 0)
        ratio = used / max(ctx, 1)
        if ratio >= 0.75:
            return max(2_000, base_cap // 8)
        if ratio >= 0.60:
            return max(3_000, base_cap // 4)
        if ratio >= 0.40:
            return max(5_000, base_cap // 2)
        return base_cap

    def _cap_tool_result(self, content: str) -> str:
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
        if not messages_to_compress:
            return ""
        if not getattr(self, "ollama", None):
            return ""

        if self._recovery_force_tool_calls > 0:
            return ""

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
        prior = self._compression_summary

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
            summary = await self.ollama.complete(
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content},
                ],

                options={"num_predict": 2048, "temperature": 0.1},
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
        cfg = get_config()
        effective_predict = (
            self._fit_num_predict_to_ctx(num_predict, num_ctx)
            if num_predict is not None
            else self._fit_num_predict_to_ctx(
                getattr(cfg, "ollama_num_predict", 32768), num_ctx
            )
        )

        _tools_count = len(self._tools_ollama) if self._tools_ollama is not None else 20
        _tools_overhead = _tools_count * 500
        effective_input_ctx = max(1024, num_ctx - effective_predict - _tools_overhead)
        budget = effective_input_ctx * 3
        total = sum(
            len(str(m.get("content") or ""))
            + len(str(m.get("tool_calls") or ""))
            + len(str(m.get("thinking") or ""))
            for m in self.state.conversation
        )
        if total <= budget:
            return

        logger.warning(
            "Pre-call char budget exceeded: %d chars > %d budget (num_ctx=%d) — compressing",
            total, budget, num_ctx,
        )

        assistant_indices = [
            i for i, m in enumerate(self.state.conversation)
            if m.get("role") == "assistant" and m.get("thinking")
        ]

        for idx in assistant_indices[:-3]:
            thinking_len = len(str(self.state.conversation[idx].get("thinking", "")))
            self.state.conversation[idx].pop("thinking", None)
            total -= thinking_len
            if total <= budget:
                logger.info("Budget restored after thinking strip (%d msgs)", len(assistant_indices))
                return

        compress_cap = max(300, budget // max(1, len(self.state.conversation)))
        first_user_seen = False
        for msg in self.state.conversation:
            role = msg.get("role")
            if role == "user" and not first_user_seen:
                first_user_seen = True
                continue
            if role in ("tool", "user"):
                content = str(msg.get("content", ""))
                if len(content) > compress_cap:
                    msg["content"] = content[:compress_cap] + f"...[hard-trimmed {len(content)} chars]"

        total = sum(
            len(str(m.get("content") or ""))
            + len(str(m.get("thinking") or ""))
            for m in self.state.conversation
        )
        if total <= budget:
            return

        _non_system = [m for m in self.state.conversation if m.get("role") != "system"]
        _keep_recent_non_sys = 15
        _candidates = _non_system[:max(0, len(_non_system) - _keep_recent_non_sys)]
        if len(_candidates) >= 5:
            _summary = await self._call_compression_llm(_candidates)
            if _summary:
                self._compression_summary = _summary

                self.state.conversation = [
                    m for m in self.state.conversation
                    if not str(m.get("content", "")).startswith("[SYSTEM: COMPRESSION SUMMARY")
                ]

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

                total = sum(
                    len(str(m.get("content") or "")) + len(str(m.get("thinking") or ""))
                    for m in self.state.conversation
                )
                if total <= budget:
                    return

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

        if s.injection_points:
            untested = get_untested_injection_points(s)
            all_ips = s.injection_points
            tested_count = len(all_ips) - len(untested)

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
        if not self._session and not self.state.hypothesis_queue and not self.state.evidence_log:
            return ""

        parts: list[str] = ["[SYSTEM: PINNED CONTEXT — confirmed findings, hypotheses, gaps]"]
        added_any = False

        if self._session and self._session.vulnerabilities:
            vulns = self._session.vulnerabilities[:10]
            vlines = [f"  - {v.get('finding', '')[:120]}" for v in vulns]
            parts.append(f"CONFIRMED VULNS ({len(self._session.vulnerabilities)}):")
            parts.extend(vlines)
            added_any = True

        pending_hyps = self.state.get_pending_hypotheses(max_items=5)
        if pending_hyps:
            parts.append("ACTIVE HYPOTHESES TO TEST:")
            for h in pending_hyps:
                parts.append(f"  [{h.get('id','')}] {h.get('claim','')[:100]}")
                if h.get("test_plan"):
                    parts.append(f"    → {h.get('test_plan','')[:80]}")
            added_any = True

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
        lines: list[str] = ["[SYSTEM: HANDOFF SUMMARY — task progress & orientation]"]

        original_task = ""
        for msg in self.state.conversation:
            if msg.get("role") == "user":
                original_task = str(msg.get("content", ""))[:300]
                break
        if original_task:
            lines.append(f"## Goal\n{original_task}")

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

        active_objs = [
            o for o in (self.state.objective_queue or [])
            if o.get("status") == "pending"
        ][:3]
        for obj in active_objs:
            obj_text = str(obj.get("title") or obj.get("description") or "").strip()
            if obj_text:
                in_progress_lines.append(f"  → {obj_text[:100]}")

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
            return ""
        return "\n".join(lines)

    def _compress_old_tool_outputs(self, *, aggressive: bool = False) -> None:
        non_system = [m for m in self.state.conversation if m.get("role") != "system"]
        keep_window = 10 if aggressive else 20
        if len(non_system) <= keep_window:
            return

        stub_max = 100 if (aggressive or self.state.iteration > 100) else 200

        force_recompress = aggressive

        compress_count = 0
        boundary_ids = set(id(m) for m in non_system[-keep_window:])

        for msg in self.state.conversation:
            if id(msg) in boundary_ids:
                continue
            role = msg.get("role", "")
            content = str(msg.get("content", ""))
            is_stub = content.startswith("[COMPRESSED]")

            if role == "tool" and not is_stub and len(content) > 300:
                key_info = AgentState._extract_key_info(content, max_chars=stub_max)
                msg["content"] = f"[COMPRESSED] {key_info.strip()}"
                compress_count += 1
            elif role == "tool" and is_stub and force_recompress and len(content) > stub_max + 20:

                msg["content"] = content[: stub_max + len("[COMPRESSED] ")]
                compress_count += 1

        if compress_count:
            logger.debug(
                "Compressed %d tool outputs at iter %d (aggressive=%s, stub=%d chars)",
                compress_count, self.state.iteration, aggressive, stub_max,
            )
