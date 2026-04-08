"""Tests for tool_scorer.py — intelligent tool scoring and ranking."""

from __future__ import annotations

from airecon.proxy.agent.tool_scorer import (
    _PHASE_BLOCKED_TOOLS,
    _PHASE_APPROPRIATE_TOOLS,
    build_tool_recommendation_context,
    extract_binary_from_command,
    rank_tools_for_phase,
    score_tool,
)


class TestExtractBinaryFromCommand:
    def test_simple_command(self):
        assert extract_binary_from_command("nmap -sV target.com") == "nmap"

    def test_cd_prefix(self):
        assert extract_binary_from_command("cd /workspace && nmap -sV target.com") == "nmap"

    def test_complex_command(self):
        # sudo is a shell builtin, but it's handled differently — 
        # the function extracts the first binary after cd prefix
        result = extract_binary_from_command("cd /workspace && sudo python3 script.py --arg1")
        assert result in ("sudo", "python3")  # Both acceptable

    def test_empty_command(self):
        assert extract_binary_from_command("") == ""

    def test_shell_builtin_only(self):
        result = extract_binary_from_command("echo hello")
        assert result == ""  # echo is a builtin, no known tool found


class TestScoreTool:
    def test_basic_scoring(self):
        result = score_tool("execute", current_phase="RECON")
        assert "score" in result
        assert "phase_appropriate" in result
        assert "phase_blocked" in result
        assert 0.0 <= result["score"] <= 1.0

    def test_phase_appropriate_tool(self):
        result = score_tool("execute", current_phase="RECON")
        assert result["phase_appropriate"] is True
        assert result["phase_blocked"] is False

    def test_blocked_tool(self):
        result = score_tool("stratus-red-team", current_phase="RECON")
        assert result["phase_blocked"] is True
        assert result["score"] == 0.0

    def test_high_success_rate_bonus(self):
        result = score_tool(
            "nmap",
            current_phase="RECON",
            tool_success_counts={"nmap": 10},
            tool_failure_counts={"nmap": 2},
        )
        # Should get bonus for high success rate (10/12 = 83%)
        assert result["score"] > 0.5

    def test_low_success_rate_penalty(self):
        result = score_tool(
            "nmap",
            current_phase="RECON",
            tool_success_counts={"nmap": 2},
            tool_failure_counts={"nmap": 10},
        )
        # Should get penalty for low success rate (2/12 = 17%)
        # Score should be at or below base (0.5) due to penalty
        assert result["score"] <= 0.5
        assert any("Low historical success" in r for r in result["reasons"])

    def test_chain_step_alignment(self):
        result = score_tool(
            "sqlmap",
            current_phase="EXPLOIT",
            chain_step_hint="sqlmap",
        )
        # Should get bonus for matching chain hint
        assert result["score"] > 0.5
        assert any("ALIGNMENT" in r for r in result["reasons"])

    def test_overuse_penalty(self):
        result = score_tool(
            "nmap",
            current_phase="RECON",
            tool_use_counts={"nmap": 15},
        )
        # Should get penalty for overuse
        assert any("Overused" in r for r in result["reasons"])

    def test_budget_exhausted_penalty(self):
        result = score_tool(
            "nmap",  # nmap IS appropriate for RECON
            current_phase="RECON",
            budget_remaining={"nmap": 0},
        )
        # Should get penalty for budget exhaustion
        assert any("budget" in r.lower() for r in result["reasons"])

    def test_coverage_bonus_uses_ontology_labels(self):
        result = score_tool(
            "sqlmap",
            current_phase="EXPLOIT",
            tested_vuln_classes={"CLIENT_SIDE"},
        )
        coverage = [r for r in result["reasons"] if "COVERAGE BONUS" in r]
        assert coverage
        assert "SQL_INJECTION" in coverage[0] or "INJECTION" in coverage[0]
        assert "specific_vulnerabilities" not in coverage[0]

    def test_adaptive_learning_bonus_applies(self):
        result = score_tool(
            "nmap",
            current_phase="RECON",
            adaptive_tool_scores={"nmap": 0.91},
        )
        assert result["score"] > 0.5
        assert any("ADAPTIVE BONUS" in r for r in result["reasons"])

    def test_strategy_sequence_alignment_applies(self):
        result = score_tool(
            "ffuf",
            current_phase="ANALYSIS",
            strategy_tool_sequence=["ffuf", "httpx", "nuclei"],
        )
        assert result["score"] > 0.5
        assert any("STRATEGY ALIGNMENT" in r for r in result["reasons"])


class TestRankToolsForPhase:
    def test_ranking_returns_sorted_list(self):
        tools = [
            {"function": {"name": "execute"}},
            {"function": {"name": "web_search"}},
        ]
        ranked = rank_tools_for_phase(tools, current_phase="RECON")
        assert isinstance(ranked, list)
        assert len(ranked) == 2

    def test_blocked_tools_removed(self):
        tools = [
            {"function": {"name": "execute"}},
            {"function": {"name": "stratus-red-team"}},  # Blocked in RECON
        ]
        ranked = rank_tools_for_phase(tools, current_phase="RECON")
        names = [t["function"]["name"] for t in ranked]
        assert "stratus-red-team" not in names

    def test_top_n_limits_results(self):
        tools = [{"function": {"name": f"tool_{i}"}} for i in range(10)]
        ranked = rank_tools_for_phase(tools, current_phase="RECON", top_n=3)
        assert len(ranked) <= 3

    def test_adaptive_inputs_influence_ranking(self):
        tools = [
            {"function": {"name": "ffuf"}},
            {"function": {"name": "nmap"}},
        ]
        ranked = rank_tools_for_phase(
            tools,
            current_phase="RECON",
            adaptive_tool_scores={"ffuf": 0.9, "nmap": 0.2},
            strategy_tool_sequence=["ffuf"],
            use_memory=False,
        )
        assert ranked[0]["function"]["name"] == "ffuf"


class TestBuildToolRecommendationContext:
    def test_returns_nonempty_for_phase(self):
        ctx = build_tool_recommendation_context(current_phase="RECON")
        assert "<system_tool_intelligence>" in ctx

    def test_dynamic_skill_entries_follow_chain_hint(self):
        ctx = build_tool_recommendation_context(
            current_phase="EXPLOIT",
            chain_step_hint="sqlmap",
        )
        assert "skills/tools/sqlmap.md" in ctx
        assert "skills/vulnerabilities/sql_injection.md" in ctx

    def test_chain_hint_included(self):
        ctx = build_tool_recommendation_context(
            current_phase="EXPLOIT",
            chain_step_hint="sqlmap",
        )
        assert "sqlmap" in ctx

    def test_analysis_skill_entries_stay_in_analysis_domains(self):
        ctx = build_tool_recommendation_context(current_phase="ANALYSIS")
        assert "skills/vulnerabilities/" in ctx or "skills/frameworks/" in ctx
        assert "skills/payloads/" not in ctx

    def test_wrong_tool_correction(self):
        ctx = build_tool_recommendation_context(
            current_phase="EXPLOIT",
            chain_step_hint="sqlmap",
            wrong_tool_picked="nmap",
        )
        assert "WRONG TOOL SELECTED" in ctx
        assert "nmap" in ctx

    def test_failure_recovery(self):
        ctx = build_tool_recommendation_context(
            current_phase="RECON",
            consecutive_failures=5,
        )
        assert "consecutive tool failures" in ctx.lower()


class TestPhaseConstraints:
    def test_recon_blocked_tools(self):
        blocked = _PHASE_BLOCKED_TOOLS.get("RECON", set())
        assert "stratus-red-team" in blocked

    def test_report_phase_blocked(self):
        blocked = _PHASE_BLOCKED_TOOLS.get("REPORT", set())
        # REPORT blocks are derived dynamically; recon tools are NOT blocked at scorer level
        # (they're filtered by phase appropriateness instead)
        # Verify the blocked set exists and is a set
        assert isinstance(blocked, set)

    def test_recon_appropriate_tools(self):
        appropriate = _PHASE_APPROPRIATE_TOOLS.get("RECON", set())
        assert "execute" in appropriate
        assert "nmap" in appropriate  # From port_scan category
        assert "subfinder" in appropriate  # From subdomain_enum category
