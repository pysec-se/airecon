from __future__ import annotations

from typing import Any

from ..data_loader import severity_to_int


def maybe_inject_mentor_analysis(
    agent: Any,
    current_phase: Any,
    all_results: dict[int, tuple],
) -> None:
    mentor_phases = {"ANALYSIS", "EXPLOIT"}
    in_mentor_phase = current_phase.value.upper() in mentor_phases
    if not (all_results and in_mentor_phase and agent.state.evidence_log):
        return

    mentor_tool_name = all_results[max(all_results.keys())][2]
    last_ev = agent.state.evidence_log[-1]
    last_sev = severity_to_int(last_ev.get("severity", 1))
    trigger_mentor = (
        last_sev >= 4
        or agent._mentor_tool_call_count % 3 == 0
    )
    if not trigger_mentor:
        return

    mentor_msg = agent._build_mentor_analysis(
        current_phase=current_phase,
        tool_name=mentor_tool_name,
        evidence_added=True,
    )

    agent.state.conversation = [
        m for m in agent.state.conversation
        if not m.get("content", "").startswith("<mentor_analysis")
    ]
    agent.state.conversation.append(
        {"role": "system", "content": mentor_msg}
    )
