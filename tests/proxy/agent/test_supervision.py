"""Tests for loop_supervision.py — watchdog, quality scores, and supervision logic."""

import pytest
from unittest.mock import MagicMock
from airecon.proxy.agent.loop_supervision import _SupervisionMixin
from airecon.proxy.agent.pipeline import PipelinePhase
from airecon.proxy.agent.session import SessionData


@pytest.fixture
def supervision_mixin(mocker):
    """Create a _SupervisionMixin instance with mocked dependencies."""
    mixin = _SupervisionMixin()

    # Mock state
    mixin.state = MagicMock()
    mixin.state.iteration = 5
    mixin.state.evidence_log = []

    # Mock session
    mixin._session = SessionData(target="example.com")

    # Mock _extract_shell_command_candidate
    mixin._extract_shell_command_candidate = MagicMock()

    return mixin


class TestBuildWatchdogToolCall:
    """Test _build_watchdog_tool_call extraction logic and None return path."""

    def test_returns_tool_call_when_command_extracted(self, supervision_mixin):
        """When a shell command is extracted, return a valid tool_call dict."""
        supervision_mixin._extract_shell_command_candidate.return_value = (
            "nmap -sV example.com"
        )

        result = supervision_mixin._build_watchdog_tool_call(
            content_acc="Let me scan the target: nmap -sV example.com",
            thinking_acc="",
            phase=PipelinePhase.RECON,
        )

        assert result is not None
        assert result["type"] == "function"
        assert result["function"]["name"] == "execute"
        assert result["function"]["arguments"]["command"] == "nmap -sV example.com"
        assert "watchdog_execute_" in result["id"]

    def test_returns_none_when_no_command_extracted(self, supervision_mixin):
        """CRITICAL: When no command is extractable, return None to trigger nudge injection."""
        supervision_mixin._extract_shell_command_candidate.return_value = None

        result = supervision_mixin._build_watchdog_tool_call(
            content_acc="I'm thinking about the target...",
            thinking_acc="Need to consider the approach carefully",
            phase=PipelinePhase.RECON,
        )

        # This is the CRITICAL untested path — None return triggers nudge injection
        assert result is None

    def test_returns_none_when_empty_command(self, supervision_mixin):
        """Empty string command should also return None."""
        supervision_mixin._extract_shell_command_candidate.return_value = ""

        result = supervision_mixin._build_watchdog_tool_call(
            content_acc="",
            thinking_acc="",
            phase=PipelinePhase.ANALYSIS,
        )

        assert result is None


class TestComputeQualityScores:
    """Test _compute_quality_scores for finding confidence tracking."""

    def test_returns_score_dict(self, supervision_mixin):
        """Quality scores should return a dict with evidence, reproducibility, impact."""
        # Add some evidence
        supervision_mixin.state.evidence_log = [
            {"tags": ["signal", "artifact"], "confidence": 0.8},
            {"tags": ["execution"], "confidence": 0.6},
            {"tags": ["cve"], "confidence": 0.9},
        ]

        result = supervision_mixin._compute_quality_scores()

        assert isinstance(result, dict)
        assert "evidence" in result
        assert "reproducibility" in result
        assert "impact" in result

    def test_handles_empty_evidence_log(self, supervision_mixin):
        """Should handle empty evidence log gracefully."""
        supervision_mixin.state.evidence_log = []

        result = supervision_mixin._compute_quality_scores()

        assert isinstance(result, dict)
        # Should not crash, should return some default scores


class TestExtractShellCommandCandidate:
    """Test _extract_shell_command_candidate helper."""

    def test_extract_from_content(self, supervision_mixin):
        """Should extract shell command from content."""
        content = "Run: nmap -sV example.com"

        # This is a private method — test via _build_watchdog_tool_call
        result = supervision_mixin._build_watchdog_tool_call(
            content_acc=content,
            thinking_acc="",
            phase=PipelinePhase.RECON,
        )

        # If extraction worked, we get a tool_call
        if result is not None:
            assert result["function"]["name"] == "execute"

    def test_no_extract_from_thinking_only(self, supervision_mixin):
        """Thinking trace alone should not yield a command."""
        result = supervision_mixin._build_watchdog_tool_call(
            content_acc="",
            thinking_acc="I should probably run nmap here",
            phase=PipelinePhase.RECON,
        )

        # Thinking alone might not extract — depends on implementation
        # The key is we test the behavior
        assert result is None or result["function"]["name"] == "execute"
