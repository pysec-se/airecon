from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("airecon.agent.meta_reasoning")


class MetaReasoningEngine:
    """Self-reflection and self-consistency engine.

    Works alongside the main agent loop to improve reasoning quality without
    requiring a more capable model.
    """

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

    # ── Meta-Reasoning Reflection ────────────────────────────────────────────

    def should_reflect(self, current_iteration: int) -> bool:
        """Check if it's time for a meta-reasoning reflection cycle."""
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
    ) -> str:
        """Build a prompt that asks the LLM to reflect on its reasoning."""
        action_summary = "\n".join(
            f"- iter {a.get('iteration', '?')}: tool={a.get('tool', '?')}, "
            f"success={a.get('success', False)}"
            for a in recent_actions[-20:]
        )

        prompt = (
            "META-REASONING REFLECTION\n"
            "You are analyzing your own recent reasoning and tool usage as a "
            "security testing AI. Critique your approach honestly.\n\n"
            f"Phase: {phase}\n"
            f"Iterations: {iterations_completed}\n"
            f"Vulnerabilities found: {vulnerabilities_found}\n"
            f"Failures: {failures}\n\n"
            f"Recent tool actions:\n{action_summary}\n\n"
            "Questions to answer:\n"
            "1. Are you stuck in a repetitive pattern?\n"
            "2. Are you using the right tools for this phase?\n"
            "3. What assumptions have you made that might be wrong?\n"
            "4. What different approach should you try next?\n"
            "5. Based on what you've learned so far, what is the single most\n"
            "   important thing to focus on in the next 5 iterations?\n\n"
            "Answer concisely. Provide ONE concrete action to take next."
        )
        return prompt

    def record_reflection_hint(self, hint: str) -> None:
        """Store a reflection hint for injection into future LLM context."""
        self.hints.append(hint)
        # Keep only last 5 hints
        if len(self.hints) > 5:
            self.hints = self.hints[-5:]

    def get_reflection_context(self) -> str | None:
        """Build a system message from accumulated reflection hints."""
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

    # ── Self-Consistency Check ───────────────────────────────────────────────

    def needs_consistency_check(
        self,
        decision: str,
        context: dict[str, Any],
    ) -> bool:
        """Determine if a decision is important enough to warrant consistency checks."""
        return decision in (
            "vulnerability_severity",
            "vulnerability_classification",
            "exploit_path",
            "final_report",
        )

    def build_consistency_check_prompt(
        self,
        question: str,
        initial_answer: str,
        context: dict[str, Any],
    ) -> str:
        """Build a prompt that explores alternative reasoning paths."""
        ctx_str = "\n".join(f"- {k}: {v}" for k, v in context.items())
        return (
            "SELF-CONSISTENCY CHECK\n"
            "You previously reasoned about this question:\n"
            f"{question}\n\n"
            f"Your initial answer was: {initial_answer}\n\n"
            f"Context:\n{ctx_str}\n\n"
            "Re-analyze this question using a DIFFERENT reasoning path.\n"
            "Start from different assumptions. Think from another angle.\n"
            "Do NOT try to agree with your initial answer — be independent.\n"
            "If your new conclusion is different, explain why.\n"
            "If it agrees, confirm why you're confident.\n"
            "Answer: ..."
        )

    def merge_consistency_results(
        self,
        initial: str,
        alternatives: list[str],
    ) -> str:
        """Merge consistency check results and find consensus."""
        all_answers = [initial] + alternatives
        most_common = max(set(all_answers), key=all_answers.count)
        self.consistency_checks += 1

        if all(a == most_common for a in all_answers):
            logger.info(
                "[MetaReasoning] Self-consistency check PASSED: "
                "all %d paths agree: %s",
                len(all_answers),
                most_common[:100],
            )
            return most_common

        logger.warning(
            "[MetaReasoning] Self-consistency check DIVERGED: "
            "%d paths, consensus=%s (initial=%s)",
            len(all_answers),
            most_common[:80],
            initial[:80],
        )
        return most_common

    def mark_iteration(self) -> None:
        self.reflection_count += 1
        self.last_reflection_iteration = time.monotonic()

    def should_retry_with_consistency(self, decision: str) -> bool:
        return decision in (
            "vulnerability_severity",
            "vulnerability_classification",
            "exploit_path",
            "final_report",
        )
