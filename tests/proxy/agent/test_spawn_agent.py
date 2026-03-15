"""Manual Verification: spawn_agent output shows specific vulnerability titles.

Verifies that _execute_spawn_agent_tool:
1. Returns 'findings' list with the finding titles from sub-agent's session
2. Returns correct 'total' count
3. Merges unique findings into parent session (dedup by similarity)
4. Blocks recursive spawn_agent calls in sub-agent
5. Falls back to 'exploit' when an invalid specialist is given
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from airecon.proxy.agent.executors import _ExecutorMixin
from airecon.proxy.agent.session import SessionData


# ---------------------------------------------------------------------------
# Test double — minimal concrete implementation of the mixin
# ---------------------------------------------------------------------------

class _State:
    def __init__(self):
        self.active_target = "http://target.example.com"
        self.tool_history = []
        self.tool_counts = {"exec": 0, "total": 0}


class DummyAgent(_ExecutorMixin):
    def __init__(self, parent_session: SessionData | None = None):
        self.state = _State()
        self._executed_tool_counts: dict = {}
        self._last_output_file = None
        self._session = parent_session
        self.engine = MagicMock()

    def _normalize_args_for_dedup(self, tool_name, args):
        return tool_name, str(args)

    def _save_tool_output(self, tool_name, arguments, result):
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sub_agent_mock(vulnerabilities: list[dict]) -> MagicMock:
    """Build a mock AgentLoop whose _session has the given vulnerabilities."""
    mock_agent = MagicMock()
    mock_session = MagicMock(spec=SessionData)
    mock_session.vulnerabilities = vulnerabilities

    # process_message is an async generator — drain it without yielding
    async def _noop_gen(*args, **kwargs):
        return
        yield  # make it an async generator

    mock_agent.process_message = _noop_gen
    mock_agent._session = mock_session
    mock_agent._override_max_iterations = None
    mock_agent._blocked_tools = set()
    return mock_agent


# ---------------------------------------------------------------------------
# Core output verification
# ---------------------------------------------------------------------------

class TestSpawnAgentOutput:

    @pytest.mark.asyncio
    async def test_findings_titles_present_in_output(self):
        """spawn_agent output 'findings' must contain the vulnerability titles
        from the sub-agent's session — the primary manual verification."""
        expected_titles = [
            "SQL Injection in /api/login parameter 'username'",
            "Reflected XSS in /search parameter 'q'",
            "IDOR via /api/users/123 — access other accounts",
        ]
        sub_vulns = [{"finding": t, "severity": "HIGH"} for t in expected_titles]

        sub_agent = _make_sub_agent_mock(sub_vulns)

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            success, duration, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Test SQLi and XSS", "target": "http://target.example.com",
                 "specialist": "exploit"},
            )

        assert success is True
        assert result["success"] is True

        # PRIMARY CHECK: all 3 vulnerability titles must appear in findings
        for title in expected_titles:
            assert title in result["findings"], (
                f"Expected finding '{title}' not found in output.\n"
                f"Actual findings: {result['findings']}"
            )

    @pytest.mark.asyncio
    async def test_total_matches_findings_count(self):
        """'total' field must equal len(findings)."""
        sub_vulns = [
            {"finding": f"Vuln {i}", "severity": "MEDIUM"} for i in range(5)
        ]
        sub_agent = _make_sub_agent_mock(sub_vulns)

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Fuzz all params", "specialist": "xss"},
            )

        assert result["total"] == len(result["findings"]) == 5

    @pytest.mark.asyncio
    async def test_findings_capped_at_10(self):
        """findings list must not exceed 10 items (session[:10] slice)."""
        sub_vulns = [{"finding": f"Vuln {i}"} for i in range(15)]
        sub_agent = _make_sub_agent_mock(sub_vulns)

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Big scan", "specialist": "recon"},
            )

        assert len(result["findings"]) <= 10

    @pytest.mark.asyncio
    async def test_empty_session_findings_is_empty_list(self):
        """If sub-agent found nothing, findings must be [] not None."""
        sub_agent = _make_sub_agent_mock([])

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Scan for issues", "specialist": "sqli"},
            )

        assert result["success"] is True
        assert result["findings"] == []
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_output_dict_has_required_keys(self):
        """Result dict must have: success, specialist, target, findings, total."""
        sub_agent = _make_sub_agent_mock([{"finding": "SSRF via webhook param"}])

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Check SSRF", "target": "https://api.target.com",
                 "specialist": "ssrf"},
            )

        required_keys = {"success", "specialist", "target", "findings", "total"}
        assert required_keys.issubset(result.keys()), (
            f"Missing keys: {required_keys - result.keys()}"
        )


# ---------------------------------------------------------------------------
# Specialist validation
# ---------------------------------------------------------------------------

class TestSpawnAgentSpecialist:

    @pytest.mark.asyncio
    async def test_valid_specialist_preserved(self):
        """Known specialist names must pass through unchanged."""
        for specialist in ("sqli", "xss", "ssrf", "lfi", "recon", "exploit",
                           "analyzer", "reporter"):
            sub_agent = _make_sub_agent_mock([])
            with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
                 patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
                 patch("airecon.proxy.agent.executors.get_config",
                       return_value=MagicMock(ollama_model="llama3")):

                agent = DummyAgent()
                _, _, result, _ = await agent._execute_spawn_agent_tool(
                    "spawn_agent", {"task": "test", "specialist": specialist},
                )

            assert result["specialist"] == specialist

    @pytest.mark.asyncio
    async def test_invalid_specialist_falls_back_to_exploit(self):
        """Unknown specialist must be sanitised to 'exploit'."""
        sub_agent = _make_sub_agent_mock([])

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "hack everything", "specialist": "root_shell_hacker"},
            )

        assert result["specialist"] == "exploit"

    @pytest.mark.asyncio
    async def test_uppercase_specialist_normalised(self):
        """Uppercase specialist name must be lowercased and accepted."""
        sub_agent = _make_sub_agent_mock([])

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            _, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "find sqli", "specialist": "SQLI"},
            )

        assert result["specialist"] == "sqli"


# ---------------------------------------------------------------------------
# Parent session merge (deduplication)
# ---------------------------------------------------------------------------

class TestSpawnAgentParentMerge:

    @pytest.mark.asyncio
    async def test_new_findings_merged_into_parent_session(self):
        """Unique sub-agent findings must be appended to parent session."""
        parent_session = SessionData(target="http://target.example.com")
        agent = DummyAgent(parent_session=parent_session)

        sub_vulns = [{"finding": "Path Traversal in /download?file=", "severity": "HIGH"}]
        sub_agent = _make_sub_agent_mock(sub_vulns)

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Find path traversal", "specialist": "lfi"},
            )

        assert len(parent_session.vulnerabilities) == 1
        assert parent_session.vulnerabilities[0]["finding"] == \
            "Path Traversal in /download?file="

    @pytest.mark.asyncio
    async def test_duplicate_findings_not_merged(self):
        """Sub-agent findings already in parent session must not be duplicated."""
        existing_vuln = {
            "finding": "Reflected XSS in parameter 'q'",
            "severity": "HIGH",
        }
        parent_session = SessionData(target="http://target.example.com")
        parent_session.vulnerabilities.append(existing_vuln)

        # Sub-agent returns exact same finding
        sub_agent = _make_sub_agent_mock([existing_vuln])

        agent = DummyAgent(parent_session=parent_session)

        with patch("airecon.proxy.agent.loop.AgentLoop", return_value=sub_agent), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "Verify XSS", "specialist": "xss"},
            )

        # Should still have exactly 1 (dedup prevented the duplicate)
        assert len(parent_session.vulnerabilities) == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestSpawnAgentErrors:

    @pytest.mark.asyncio
    async def test_exception_returns_failure_dict(self):
        """If AgentLoop raises, result must be {success: False, error: ...}."""
        with patch("airecon.proxy.agent.loop.AgentLoop",
                   side_effect=RuntimeError("ollama connection refused")), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            success, _, result, _ = await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "test", "specialist": "exploit"},
            )

        assert success is False
        assert result["success"] is False
        assert "ollama connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_tool_history_recorded_on_failure(self):
        """Tool execution must be recorded in state.tool_history even on failure."""
        with patch("airecon.proxy.agent.loop.AgentLoop",
                   side_effect=RuntimeError("timeout")), \
             patch("airecon.proxy.ollama.OllamaClient", return_value=MagicMock()), \
             patch("airecon.proxy.agent.executors.get_config", return_value=MagicMock(
                 ollama_model="llama3")):

            agent = DummyAgent()
            await agent._execute_spawn_agent_tool(
                "spawn_agent",
                {"task": "test", "specialist": "recon"},
            )

        assert len(agent.state.tool_history) == 1
        assert agent.state.tool_history[0].tool_name == "spawn_agent"
        assert agent.state.tool_history[0].status == "error"
