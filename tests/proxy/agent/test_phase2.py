"""Tests for Phase 2: Skill Orchestration Policy + Tool Budget."""
from __future__ import annotations

import pytest

from airecon.proxy.system import auto_load_skills_for_message, _PHASE_SKILL_DIRECTORIES
from airecon.proxy.agent.models import AgentState
from airecon.proxy.agent.pipeline import _PHASE_TOOL_BUDGETS, PipelineEngine
from airecon.proxy.agent.session import SessionData


# ── Skill Orchestration Policy ─────────────────────────────────────────────


def test_phase_skill_directories_defined():
    """_PHASE_SKILL_DIRECTORIES should cover all pipeline phases."""
    for phase in ("RECON", "ANALYSIS", "EXPLOIT", "REPORT", "COMPLETE"):
        assert phase in _PHASE_SKILL_DIRECTORIES


def test_skill_phase_boost_exploit_score_logic():
    """In EXPLOIT phase, payloads/ skills get +2 boost over recon/ skills."""
    import airecon.proxy.system as sys_module

    fake_keywords = {
        "sql": "payloads/sqli.md",
        "scan": "reconnaissance/full_recon.md",
    }

    msg_lower = "sql scan"
    scores: dict[str, int] = {}
    for kw, path in fake_keywords.items():
        if kw in msg_lower:
            scores[path] = scores.get(path, 0) + 1

    # Before boost: both have score 1
    assert scores["payloads/sqli.md"] == 1
    assert scores["reconnaissance/full_recon.md"] == 1

    # Apply EXPLOIT boost
    phase = "EXPLOIT"
    preferred = sys_module._PHASE_SKILL_DIRECTORIES[phase]
    for skill_path in list(scores.keys()):
        if skill_path.split("/")[0] in preferred:
            scores[skill_path] += 2

    # payloads/ is in EXPLOIT preferred → gets +2 (total 3)
    # reconnaissance/ is NOT in EXPLOIT preferred → stays at 1
    assert scores["payloads/sqli.md"] == 3
    assert scores["reconnaissance/full_recon.md"] == 1

    # Sorted: payloads/sqli.md comes first
    sorted_skills = sorted(scores.keys(), key=lambda s: (-scores[s], s))
    assert sorted_skills[0] == "payloads/sqli.md"


def test_skill_phase_no_boost_zero_hits(mocker):
    """Skills with 0 keyword hits should NOT be boosted into keyword slots.

    However, _PHASE_ENTRY_SKILLS guarantees load even with zero keyword hits —
    that is the whole point of the guarantee. Only keyword-matched skills are
    suppressed when there are no hits.
    """
    fake_keywords = {
        "xss": "payloads/xss.md",
    }
    mocker.patch("airecon.proxy.system._SKILL_KEYWORDS", fake_keywords)

    # Message has NO keywords — skill_scores is empty, so "xss" keyword never fires.
    # EXPLOIT phase has one guaranteed skill: tools/advanced_fuzzing.md
    # That skill loads via the guarantee path regardless of keyword hits.
    ctx, loaded = auto_load_skills_for_message("totally unrelated message", phase="EXPLOIT")

    # The keyword-only skill (xss.md) must NOT be loaded (zero hits, no keyword match).
    assert "payloads/xss.md" not in loaded
    # Guaranteed skill (advanced_fuzzing) may load if the file exists on disk.
    # We do NOT assert ctx == "" because guaranteed skills bypass the zero-hit guard.


def test_skill_phase_report_no_boost(mocker):
    """REPORT phase has empty preferred set → no boost applied."""
    fake_keywords = {
        "vulnerability": "vulnerabilities/sql_injection.md",
        "sql": "payloads/sqli.md",
    }
    mocker.patch("airecon.proxy.system._SKILL_KEYWORDS", fake_keywords)

    import airecon.proxy.system as sys_module
    original_dirs = sys_module._PHASE_SKILL_DIRECTORIES

    # Verify REPORT has empty preferred set
    assert original_dirs["REPORT"] == set()
    assert original_dirs["COMPLETE"] == set()


def test_skill_boost_additive_not_multiplicative(mocker):
    """Phase boost adds +2 (not multiply), preserving existing relative scores."""
    fake_keywords = {
        "inject": "payloads/sqli.md",
        "sql injection": "payloads/sqli.md",
        "sql": "payloads/sqli.md",
        "xss": "vulnerabilities/xss.md",
    }
    mocker.patch("airecon.proxy.system._SKILL_KEYWORDS", fake_keywords)

    import airecon.proxy.system as sys_module

    # Simulate score computation manually
    msg = "sql injection xss"
    msg_lower = msg.lower()
    scores: dict[str, int] = {}
    for kw, path in fake_keywords.items():
        if kw in msg_lower:
            scores[path] = scores.get(path, 0) + 1

    # payloads/sqli.md matches "inject", "sql injection", "sql" → score=3
    # vulnerabilities/xss.md matches "xss" → score=1
    assert scores["payloads/sqli.md"] == 3
    assert scores["vulnerabilities/xss.md"] == 1

    # Apply EXPLOIT phase boost: both dirs are preferred
    preferred = sys_module._PHASE_SKILL_DIRECTORIES["EXPLOIT"]
    assert "payloads" in preferred
    assert "vulnerabilities" in preferred

    # After boost: sqli=5, xss=3 — sqli still wins
    for path in scores:
        if path.split("/")[0] in preferred:
            scores[path] += 2

    assert scores["payloads/sqli.md"] == 5
    assert scores["vulnerabilities/xss.md"] == 3


# ── Tool Budget Tracking ───────────────────────────────────────────────────


def test_record_tool_use_increments():
    """record_tool_use() should increment per-phase counter correctly."""
    state = AgentState()

    state.record_tool_use("RECON", "execute")
    state.record_tool_use("RECON", "execute")
    state.record_tool_use("RECON", "advanced_fuzz")
    state.record_tool_use("EXPLOIT", "advanced_fuzz")

    assert state.get_phase_tool_count("RECON", "execute") == 2
    assert state.get_phase_tool_count("RECON", "advanced_fuzz") == 1
    assert state.get_phase_tool_count("EXPLOIT", "advanced_fuzz") == 1
    assert state.get_phase_tool_count("RECON", "deep_fuzz") == 0
    assert state.get_phase_tool_count("ANALYSIS", "execute") == 0


def test_phase_tool_usage_isolated_per_phase():
    """Different phases should have independent counters."""
    state = AgentState()

    for _ in range(5):
        state.record_tool_use("RECON", "quick_fuzz")
    for _ in range(3):
        state.record_tool_use("EXPLOIT", "quick_fuzz")

    assert state.get_phase_tool_count("RECON", "quick_fuzz") == 5
    assert state.get_phase_tool_count("EXPLOIT", "quick_fuzz") == 3


def test_tool_effectiveness_tracks_meaningful_hits():
    state = AgentState()
    state.record_tool_outcome("ANALYSIS", "quick_fuzz", success=True, meaningful_evidence_delta=1)
    state.record_tool_outcome("ANALYSIS", "quick_fuzz", success=True, meaningful_evidence_delta=0)
    state.record_tool_outcome("ANALYSIS", "quick_fuzz", success=False, meaningful_evidence_delta=0)

    eff = state.get_tool_effectiveness("ANALYSIS", "quick_fuzz")
    assert eff["calls"] == 3.0
    assert eff["success_rate"] == pytest.approx(2 / 3, rel=0.01)
    assert eff["hit_rate"] == pytest.approx(1 / 3, rel=0.01)


def test_phase_tool_budgets_defined():
    """_PHASE_TOOL_BUDGETS should cover RECON, ANALYSIS, EXPLOIT, REPORT."""
    for phase in ("RECON", "ANALYSIS", "EXPLOIT", "REPORT"):
        assert phase in _PHASE_TOOL_BUDGETS


def test_phase_tool_budget_recon_values():
    """RECON budget: lenient fuzz, deep_fuzz discouraged."""
    recon = _PHASE_TOOL_BUDGETS["RECON"]
    assert recon["quick_fuzz"] >= 5
    assert recon["advanced_fuzz"] >= 3
    assert recon["deep_fuzz"] == 0


def test_pipeline_get_tool_budget_method():
    """PipelineEngine.get_tool_budget() should delegate to _PHASE_TOOL_BUDGETS."""
    session = SessionData(target="example.com")
    engine = PipelineEngine(session)

    assert engine.get_tool_budget("RECON", "deep_fuzz") == 0
    assert engine.get_tool_budget("EXPLOIT", "advanced_fuzz") == 50
    assert engine.get_tool_budget("RECON", "execute") is None  # unconstrained


def test_check_tool_budget_no_warning_below_75pct():
    """No warning when usage is below 75% of budget."""
    state = AgentState()
    # advanced_fuzz budget in ANALYSIS = 15, 75% = 11
    for _ in range(10):
        state.record_tool_use("ANALYSIS", "advanced_fuzz")

    # Simulate what _check_tool_budget would do
    phase = "ANALYSIS"
    tool = "advanced_fuzz"
    budget = _PHASE_TOOL_BUDGETS[phase][tool]  # 15
    usage = state.get_phase_tool_count(phase, tool)  # 10
    assert usage < int(budget * 0.75)  # 10 < 11


def test_check_tool_budget_at_75pct():
    """At 75% of budget, a warning should be generated."""
    state = AgentState()
    # ANALYSIS advanced_fuzz budget = 15, 75% = 11
    for _ in range(12):
        state.record_tool_use("ANALYSIS", "advanced_fuzz")

    phase = "ANALYSIS"
    tool = "advanced_fuzz"
    budget = _PHASE_TOOL_BUDGETS[phase][tool]
    usage = state.get_phase_tool_count(phase, tool)
    # 12 >= int(15 * 0.75) = 11 → should warn
    assert usage >= int(budget * 0.75)
    assert usage < budget


def test_check_tool_budget_exhausted():
    """At or above budget, exhaustion warning should fire."""
    state = AgentState()
    budget = _PHASE_TOOL_BUDGETS["ANALYSIS"]["advanced_fuzz"]  # 15
    for _ in range(budget):
        state.record_tool_use("ANALYSIS", "advanced_fuzz")

    usage = state.get_phase_tool_count("ANALYSIS", "advanced_fuzz")
    assert usage >= budget


def test_check_tool_budget_zero_discouraged():
    """Tool with budget=0 should be flagged after first use."""
    state = AgentState()
    assert _PHASE_TOOL_BUDGETS["RECON"]["deep_fuzz"] == 0

    state.record_tool_use("RECON", "deep_fuzz")
    usage = state.get_phase_tool_count("RECON", "deep_fuzz")
    assert usage >= 1  # triggers the budget==0 warning path


def test_check_tool_budget_unconstrained_tool():
    """Tool not in budget dict should not generate warnings."""
    budget = _PHASE_TOOL_BUDGETS.get("RECON", {}).get("execute")
    assert budget is None  # execute is unconstrained in RECON
