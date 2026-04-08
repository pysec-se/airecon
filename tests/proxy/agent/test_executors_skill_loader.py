from __future__ import annotations

from unittest.mock import MagicMock

from airecon.proxy.agent.executors_skill_loader import load_skill
from airecon.proxy.agent.models import AgentState


def test_load_skill_resolves_stem_alias() -> None:
    state = AgentState()

    result = load_skill(state, "sqlmap")

    assert result["success"] is True
    assert "tools/sqlmap.md" in result["loaded_skills"]
    assert "tools/sqlmap.md" in state.skills_used


def test_load_skill_resolves_keyword_alias() -> None:
    state = AgentState()

    result = load_skill(state, "sql injection")

    assert result["success"] is True
    assert "vulnerabilities/sql_injection.md" in result["loaded_skills"]


def test_load_skill_injects_dynamic_skill_content() -> None:
    state = AgentState()

    result = load_skill(state, "graphql")

    assert result["success"] is True
    assert state.conversation
    content = state.conversation[-1]["content"]
    assert "[SKILL LOADED: protocols/graphql.md]" in content
    assert '<dynamic_skill name="protocols/graphql.md">' in content


def test_load_skill_persists_usage_when_memory_manager_present() -> None:
    state = AgentState()
    memory_manager = MagicMock()

    result = load_skill(
        state,
        "graphql",
        memory_manager=memory_manager,
        current_target="https://api.example.com/graphql",
        current_phase="ANALYSIS",
    )

    assert result["success"] is True
    memory_manager.save_skill_usage.assert_called_once()
    kwargs = memory_manager.save_skill_usage.call_args.kwargs
    assert kwargs["skill_name"] == "protocols/graphql.md"
    assert kwargs["phase"] == "ANALYSIS"
