"""Tests for Progressive Context Summarization in AgentLoop."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airecon.proxy.agent.models import AgentState


# ---------------------------------------------------------------------------
# _build_compressed_findings_summary (static helper — test via AgentLoop)
# ---------------------------------------------------------------------------


def _make_loop() -> "AgentLoop":  # type: ignore[name-defined]  # noqa: F821
    """Create a minimal AgentLoop with mocked engine and ollama."""
    from airecon.proxy.agent.loop import AgentLoop
    loop = AgentLoop.__new__(AgentLoop)
    loop.state = AgentState()
    loop.ollama = AsyncMock()
    loop.engine = MagicMock()
    loop._session = None
    loop._ctf_mode = False
    return loop


class TestBuildCompressedFindingsSummary:
    def test_returns_empty_when_nothing_to_pin(self) -> None:
        loop = _make_loop()
        result = loop._build_compressed_findings_summary()
        assert result == ""

    def test_includes_vulnerabilities(self) -> None:
        loop = _make_loop()
        session = MagicMock()
        session.vulnerabilities = [
            {"finding": "SQL injection found in login username parameter"}
        ]
        session.technologies = []
        loop._session = session

        result = loop._build_compressed_findings_summary()
        assert "CONFIRMED VULNS" in result
        assert "SQL injection" in result

    def test_includes_active_hypotheses(self) -> None:
        loop = _make_loop()
        loop.state.add_hypothesis(
            "IDOR via user_id parameter in /api/profile",
            "Send GET /api/profile with different user_id values",
        )

        result = loop._build_compressed_findings_summary()
        assert "ACTIVE HYPOTHESES" in result
        assert "IDOR via user_id" in result

    def test_includes_high_value_evidence(self) -> None:
        loop = _make_loop()
        loop.state.add_evidence(
            phase="EXPLOIT",
            source_tool="sqlmap",
            summary="SQLi confirmed in login endpoint username param via boolean-based",
            confidence=0.95,
            severity=5,
        )

        result = loop._build_compressed_findings_summary()
        assert "HIGH-VALUE EVIDENCE" in result
        assert "sqlmap" in result

    def test_excludes_low_severity_evidence(self) -> None:
        loop = _make_loop()
        loop.state.add_evidence(
            phase="RECON",
            source_tool="nmap",
            summary="Port 80 open on target host",
            confidence=0.90,
            severity=2,  # LOW — should not appear in pinned
        )

        result = loop._build_compressed_findings_summary()
        # No high-value evidence → no "HIGH-VALUE EVIDENCE" section
        assert "HIGH-VALUE EVIDENCE" not in result

    def test_pinned_context_prefix(self) -> None:
        loop = _make_loop()
        loop.state.add_hypothesis("XSS in search form parameter", "send <script>")

        result = loop._build_compressed_findings_summary()
        assert result.startswith("[SYSTEM: PINNED CONTEXT")


class TestCompressOldToolOutputs:
    def test_compresses_old_tool_messages(self) -> None:
        loop = _make_loop()
        # Add 25 non-system messages (5 old + 20 recent)
        for i in range(25):
            role = "tool" if i % 2 == 0 else "assistant"
            loop.state.conversation.append({
                "role": role,
                "content": "A" * 500 + f" result number {i}",
            })

        loop._compress_old_tool_outputs()

        # Old tool messages (first 5) should be compressed
        tool_msgs = [m for m in loop.state.conversation if m.get("role") == "tool"]
        compressed = [m for m in tool_msgs if m["content"].startswith("[COMPRESSED]")]
        assert len(compressed) > 0

    def test_does_not_compress_recent_20(self) -> None:
        loop = _make_loop()
        # Add exactly 20 non-system messages (all tool)
        for i in range(20):
            loop.state.conversation.append({
                "role": "tool",
                "content": "B" * 500,
            })

        loop._compress_old_tool_outputs()

        # All 20 are within the keep-recent window → none compressed
        compressed = [
            m for m in loop.state.conversation
            if m.get("role") == "tool" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_preserves_short_tool_outputs(self) -> None:
        loop = _make_loop()
        # 25 messages, all tool, but short content
        for i in range(25):
            loop.state.conversation.append({"role": "tool", "content": "short"})

        loop._compress_old_tool_outputs()

        # Short messages should NOT be compressed
        compressed = [
            m for m in loop.state.conversation
            if m.get("role") == "tool" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_does_not_compress_system_messages(self) -> None:
        loop = _make_loop()
        for i in range(25):
            loop.state.conversation.append({
                "role": "system",
                "content": "D" * 500,
            })

        loop._compress_old_tool_outputs()

        compressed = [
            m for m in loop.state.conversation
            if m.get("role") == "system" and m["content"].startswith("[COMPRESSED]")
        ]
        assert len(compressed) == 0

    def test_skips_already_compressed_messages(self) -> None:
        loop = _make_loop()
        # Add 25 messages where some are pre-compressed
        for i in range(25):
            content = "[COMPRESSED] already done" if i < 3 else "E" * 500
            loop.state.conversation.append({"role": "tool", "content": content})

        loop._compress_old_tool_outputs()

        # Pre-compressed messages should not have double-[COMPRESSED]
        for msg in loop.state.conversation:
            assert not msg["content"].startswith("[COMPRESSED] [COMPRESSED]")
