from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("airecon.agent.meta_reasoning")

_LATERAL_ENABLED = True
_DECISION_TYPES = {
    "vulnerability_severity": 0.6,
    "vulnerability_classification": 0.6,
    "exploit_path": 0.8,
    "final_report": 0.9,
    "attack_chaining": 0.7,
    "novel_vector_proposal": 0.9,
    "contextual_pivot": 0.8,
    "false_positive_check": 0.5,
    "escalation_path": 0.7,
}


class MetaReasoningEngine:
    """Self-reflection and self-consistency engine with lateral thinking."""

    def __init__(
        self,
        reflection_interval: int = 15,
        self_consistency_calls: int = 2,
    ):
        self.reflection_interval = reflection_interval
        self.self_consistency_calls = self_consistency_calls
        self.reflection_count = 0
        self.consistency_checks = 0
        self.hints: list[str] = []
        self.last_reflection_iteration = 0
        self.lateral_thinking_enabled = _LATERAL_ENABLED
        self._reasoning_paths: list[dict[str, Any]] = []

    def should_reflect(self, current_iteration: int) -> bool:
        return (
            current_iteration - self.last_reflection_iteration
            >= self.reflection_interval
        )

    def build_reflection_prompt(
        self,
        phase: str,
        recent_actions: list[dict[str, Any]],
        failures: int,
        vulnerabilities_found: int,
        iterations_completed: int,
        findings: list[dict[str, Any]] | None = None,
    ) -> str:
        action_summary = "\n".join(
            f"- iter {a.get('iteration', '?')}: tool={a.get('tool', '?')}, "
            f"success={a.get('success', False)}"
            for a in recent_actions[-20:]
        )

        lateral_questions = ""
        if findings and len(findings) >= 2:
            finding_summary = "\n".join(
                f"- {f.get('finding', f.get('title', 'unknown'))[:80]}"
                for f in findings[-5:]
            )
            lateral_questions = (
                "\n\nLATERAL THINKING CHALLENGE:\n"
                "You have these findings:\n"
                f"{finding_summary}\n\n"
                "Consider: Can LOW severity findings be COMBINED into HIGH impact?\n"
                "Think about attack chaining, privilege escalation, or data exfiltration paths.\n"
                "What UNCONVENTIONAL attack vectors could emerge from combining these findings?\n"
            )

        prompt = (
            "META-REASONING REFLECTION\n"
            "You are analyzing your own reasoning as a security testing AI.\n\n"
            f"Phase: {phase}\n"
            f"Iterations: {iterations_completed}\n"
            f"Vulnerabilities found: {vulnerabilities_found}\n"
            f"Failures: {failures}\n\n"
            f"Recent tool actions:\n{action_summary}\n\n"
            "Questions to answer:\n"
            "1. Are you stuck in a repetitive pattern?\n"
            "2. Are you using the right tools for this phase?\n"
            "3. What assumptions have you made that might be wrong?\n"
            "4. What DIFFERENT approach should you try?\n"
            "5. What is the most HIGH-IMPACT action for next 5 iterations?\n"
            f"{lateral_questions}\n"
            "Answer concisely. Provide ONE concrete action to take next."
        )
        return prompt

    def record_reflection_hint(self, hint: str) -> None:
        self.hints.append(hint)
        if len(self.hints) > 5:
            self.hints = self.hints[-5:]

    def get_reflection_context(self) -> str | None:
        if not self.hints:
            return None

        lines = [
            "<meta_reasoning: self-reflection insights>",
            "Your previous self-reflections identified these insights:",
        ]
        for i, h in enumerate(self.hints, 1):
            lines.append(f"{i}. {h}")
        lines.append("</meta_reasoning>")
        return "\n".join(lines)

    def needs_consistency_check(
        self,
        decision: str,
        context: dict[str, Any],
    ) -> bool:
        if not self.lateral_thinking_enabled:
            return decision in (
                "vulnerability_severity",
                "vulnerability_classification",
                "exploit_path",
                "final_report",
            )

        threshold = _DECISION_TYPES.get(decision, 0.5)

        if context.get("confidence", 0.5) < threshold:
            return True

        if context.get("iterations", 0) > 20 and decision in (
            "exploit_path",
            "attack_chaining",
        ):
            return True

        if context.get("findings_count", 0) >= 3 and decision in (
            "escalation_path",
            "attack_chaining",
        ):
            return True

        return decision in (
            "vulnerability_severity",
            "vulnerability_classification",
            "exploit_path",
            "final_report",
            "attack_chaining",
            "novel_vector_proposal",
            "contextual_pivot",
        )

    def build_consistency_check_prompt(
        self,
        question: str,
        initial_answer: str,
        context: dict[str, Any],
    ) -> str:
        reasoning_style = context.get("reasoning_style", "default")

        prompt = (
            "SELF-CONSISTENCY CHECK\n"
            "You previously reasoned about this:\n"
            f"Question: {question}\n\n"
            f"Your initial answer: {initial_answer}\n\n"
        )

        if reasoning_style == "lateral":
            prompt += (
                "Think from a COMPLETELY DIFFERENT angle:\n"
                "- What if this isn't a technical vulnerability but a logic flaw?\n"
                "- Could this be exploited via a different attack surface?\n"
                "- What if the assumption about 'secure' is wrong?\n"
            )
        elif reasoning_style == "chaining":
            prompt += (
                "Think about ATTACK CHAINING:\n"
                "- Can this finding enable other attacks?\n"
                "- What does this reveal about the system that enables escalation?\n"
                "- How could this be combined with other findings?\n"
            )
        else:
            ctx_str = "\n".join(
                f"- {k}: {v}"
                for k, v in context.items()
                if k not in ("reasoning_style", "initial_answer")
            )
            prompt += f"Context:\n{ctx_str}\n\n"
            prompt += (
                "Re-analyze using a DIFFERENT reasoning path.\n"
                "Start from different assumptions.\n"
            )

        prompt += (
            "Do NOT try to agree with your initial answer — be independent.\n"
            "If your conclusion differs, explain why.\n"
            "If it agrees, confirm why you're confident.\n"
            "Answer: ..."
        )
        return prompt

    def merge_consistency_results(
        self,
        initial: str,
        alternatives: list[str],
    ) -> str:
        all_answers = [initial] + alternatives
        most_common = max(set(all_answers), key=all_answers.count)
        self.consistency_checks += 1

        if all(a == most_common for a in all_answers):
            logger.info(
                "[MetaReasoning] Self-consistency PASSED: all %d paths agree: %s",
                len(all_answers),
                most_common[:100],
            )
            return most_common

        logger.warning(
            "[MetaReasoning] Self-consistency DIVERGED: %d paths, consensus=%s",
            len(all_answers),
            most_common[:80],
        )
        return most_common

    def mark_iteration(self) -> None:
        self.reflection_count += 1
        self.last_reflection_iteration = time.monotonic()

    def should_retry_with_consistency(self, decision: str) -> bool:
        return decision in _DECISION_TYPES

    def analyze_lateral_options(
        self,
        findings: list[dict[str, Any]],
        current_approach: str,
    ) -> list[dict[str, Any]]:
        if not findings or not self.lateral_thinking_enabled:
            return []

        options = []

        if len(findings) >= 2:
            options.append(
                {
                    "type": "chaining",
                    "description": "Combine multiple findings into attack chain",
                    "priority": len(findings) / 10,
                }
            )

        low_sev = [f for f in findings if f.get("severity", 3) <= 2]
        if low_sev:
            options.append(
                {
                    "type": "escalation",
                    "description": f"Elevate {len(low_sev)} low-severity findings to higher impact",
                    "priority": len(low_sev) / 5,
                }
            )

        if current_approach in ("sqli", "xss", "ssrf"):
            options.append(
                {
                    "type": "pivot",
                    "description": f"Pivot from {current_approach} to different attack vector",
                    "priority": 0.3,
                }
            )

        return sorted(options, key=lambda x: x["priority"], reverse=True)

    def get_reasoning_context(
        self,
        phase: str,
        findings: list[dict[str, Any]],
        iteration: int,
    ) -> str:
        if not self.lateral_thinking_enabled or not findings:
            return ""

        lines = ["<lateral_thinking>"]

        if iteration > 10 and len(findings) >= 3:
            lines.append("Consider attack chaining from multiple findings")

        if iteration > 20:
            lines.append("Explore novel vectors beyond standard vulnerability classes")

        low_sev = [f for f in findings if f.get("severity", 3) <= 2]
        if low_sev:
            lines.append(
                f"You have {len(low_sev)} LOW severity findings - "
                "analyze for escalation potential"
            )

        lines.append("</lateral_thinking>")

        if len(lines) > 3:
            return "\n".join(lines)
        return ""
