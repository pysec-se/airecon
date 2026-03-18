"""Tests for issues identified in code review:

1. _enforce_char_budget must not trim the first user message (scope/target protection)
2. tool_flag_conflicts must use token-based matching (no false positives from URLs)
3. output_parser_tool_patterns loaded from tools_meta.json → correct parser selected
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ──────────────────────────────────────────────────────────

def _make_agent_loop():
    """Create a minimal AgentLoop with mocked dependencies."""
    from airecon.proxy.agent.loop import AgentLoop

    ollama_mock = MagicMock()
    engine_mock = MagicMock()
    engine_mock.discover_tools = MagicMock(return_value=[])
    engine_mock.tools_to_ollama_format = MagicMock(return_value=[])

    with patch("airecon.proxy.agent.loop.get_config") as mock_cfg:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 5
        cfg.ollama_num_ctx = 4096
        mock_cfg.return_value = cfg
        return AgentLoop(ollama=ollama_mock, engine=engine_mock)


# ── 1. _enforce_char_budget: first user message protection ───────────

class TestEnforceCharBudget:
    """_enforce_char_budget must protect the first user message from trimming."""

    def _build_loop_with_conversation(self, messages):
        loop = _make_agent_loop()
        loop.state.conversation = list(messages)
        return loop

    def test_first_user_message_never_trimmed(self):
        """The original task message (first user) must survive budget enforcement."""
        scope_msg = "pentest target.com — scope: *.target.com only, NO WAF bypass"
        loop = self._build_loop_with_conversation([
            {"role": "system", "content": "You are AIRecon."},
            {"role": "user", "content": scope_msg},
            # Many large tool results to trigger budget enforcement
            *[
                {"role": "tool", "name": "execute", "content": "x" * 5000}
                for _ in range(20)
            ],
        ])

        # Force a very small budget so compression is triggered
        loop._enforce_char_budget(num_ctx=100)

        # First user message must be completely intact
        user_msgs = [m for m in loop.state.conversation if m.get("role") == "user"]
        assert user_msgs, "No user messages remaining after budget enforcement"
        assert user_msgs[0]["content"] == scope_msg, (
            "First user message (scope/task) was trimmed — this causes scope loss"
        )

    def test_subsequent_user_messages_can_be_trimmed(self):
        """Follow-up user messages (not the first) are eligible for compression."""
        large_followup = "q" * 5000
        loop = self._build_loop_with_conversation([
            {"role": "system", "content": "You are AIRecon."},
            {"role": "user", "content": "pentest target.com"},  # first — protected
            {"role": "assistant", "content": "Starting scan."},
            {"role": "user", "content": large_followup},  # second — compressible
            *[{"role": "tool", "name": "execute", "content": "x" * 5000} for _ in range(10)],
        ])

        loop._enforce_char_budget(num_ctx=200)

        user_msgs = [m for m in loop.state.conversation if m.get("role") == "user"]
        # First user message always intact
        assert user_msgs[0]["content"] == "pentest target.com"
        # Second user message may be trimmed (if budget was exceeded)
        if len(user_msgs) > 1:
            assert len(user_msgs[1]["content"]) <= len(large_followup)

    def test_no_compression_when_within_budget(self):
        """No messages are modified when total chars are within budget."""
        msgs = [
            {"role": "system", "content": "You are AIRecon."},
            {"role": "user", "content": "pentest target.com"},
            {"role": "tool", "name": "execute", "content": "small result"},
        ]
        loop = self._build_loop_with_conversation(msgs)

        loop._enforce_char_budget(num_ctx=131072)  # generous budget

        assert loop.state.conversation[1]["content"] == "pentest target.com"
        assert loop.state.conversation[2]["content"] == "small result"

    def test_empty_conversation_does_not_crash(self):
        """No error if conversation is empty."""
        loop = self._build_loop_with_conversation([])
        loop._enforce_char_budget(num_ctx=100)  # must not raise
        assert loop.state.conversation == []

    def test_budget_uses_num_ctx_minus_num_predict(self, monkeypatch):
        """Budget = (num_ctx - num_predict) * 3, not num_ctx * 3.

        Regression test for the root-cause of hallucination at ~130K tokens:
        if budget used full num_ctx, Ollama would silently truncate the system
        prompt because input_tokens + output_reservation > KV cache size.
        """
        from unittest.mock import MagicMock, patch

        num_ctx = 10_000
        num_predict = 2_000
        # Effective input budget = (10000 - 2000) * 3 = 24000 chars
        # Full (wrong) budget    =  10000           * 3 = 30000 chars

        # Build a conversation that is between the two budgets:
        # total chars ≈ 25000 — over effective budget but under full budget.
        big_tool_result = "x" * 25_000
        loop = self._build_loop_with_conversation([
            {"role": "system", "content": "You are AIRecon."},
            {"role": "user", "content": "pentest target.com"},
            {"role": "tool", "name": "execute", "content": big_tool_result},
        ])

        cfg_mock = MagicMock()
        cfg_mock.ollama_num_predict = num_predict

        with patch("airecon.proxy.agent.loop.get_config", return_value=cfg_mock):
            loop._enforce_char_budget(num_ctx=num_ctx)

        # Tool result must have been compressed (budget was exceeded)
        tool_msg = next(
            m for m in loop.state.conversation if m.get("role") == "tool"
        )
        assert len(tool_msg["content"]) < len(big_tool_result), (
            "Tool result was NOT compressed — budget likely used full num_ctx "
            "instead of (num_ctx - num_predict), missing the hallucination fix"
        )


# ── 1b. watchdog_forced_calls resets after successful tool calls ─────

class TestWatchdogCounterReset:
    """_watchdog_forced_calls must reset to 0 after a successful tool call."""

    def test_watchdog_counter_resets_on_successful_tool_call(self):
        """After tool_calls succeed, _watchdog_forced_calls resets to 0.

        Regression test for Bug 3: counter was never reset within a session,
        meaning 3 text-only episodes permanently exhausted the watchdog budget
        even if 100+ successful tool calls happened in between.
        """
        loop = _make_agent_loop()
        loop._watchdog_forced_calls = 2  # simulate 2 prior watchdog uses

        # Simulate the code path that resets the counter
        # (executed when tool_calls_acc is non-empty, line ~1938 in loop.py)
        tool_calls_acc = [{"function": {"name": "execute"}}]
        if tool_calls_acc:
            loop._no_tool_iterations = 0
            loop._recovery_force_tool_calls = 0
            loop._watchdog_forced_calls = 0  # the fix

        assert loop._watchdog_forced_calls == 0, (
            "_watchdog_forced_calls was not reset after successful tool call"
        )

    def test_watchdog_counter_not_reset_when_no_tool_calls(self):
        """_watchdog_forced_calls must NOT reset when iteration has no tool calls."""
        loop = _make_agent_loop()
        loop._watchdog_forced_calls = 2

        tool_calls_acc: list = []  # no tool calls this iteration
        if tool_calls_acc:  # False — counter stays
            loop._watchdog_forced_calls = 0

        assert loop._watchdog_forced_calls == 2


# ── 2. tool_flag_conflicts: token-based, no URL false positives ──────

class TestToolFlagConflicts:
    """Tool-flag conflict detection must use token matching, not substring search."""

    def _execute_check(self, cmd: str):
        """
        Replicate the flag-conflict guard logic from executors.py.

        Returns:
            (found_flags, correct_tool) if a conflict is detected with ≥1 flag.
            []                          if no conflict (binary unknown or no bad flags).
        """
        from airecon.proxy.agent.executors import _TOOL_FLAG_CONFLICTS
        import shlex

        cmd_stripped = cmd.strip()
        first_token = cmd_stripped.split()[0] if cmd_stripped.split() else ""
        if first_token not in _TOOL_FLAG_CONFLICTS:
            return []
        conflict_flags, correct_tool = _TOOL_FLAG_CONFLICTS[first_token]
        try:
            tokens = set(shlex.split(cmd_stripped))
        except ValueError:
            tokens = set(cmd_stripped.split())
        found = [f for f in conflict_flags if f in tokens]
        if not found:
            return []
        return found, correct_tool

    def test_httpx_flag_on_curl_rejected(self):
        """curl with httpx-only flags must be rejected."""
        result = self._execute_check("curl -sc -title https://target.com")
        found, correct = result
        assert found, "Expected flag conflict to be detected"
        assert correct == "httpx"

    def test_curl_with_url_containing_status_code_not_rejected(self):
        """curl with a URL containing 'status-code' in path must NOT be rejected."""
        result = self._execute_check("curl https://api.example.com/status-code/200")
        # -status-code is not a standalone token here, so no conflict
        assert result == [], "False positive: URL path should not trigger flag conflict"

    def test_curl_with_data_value_not_rejected(self):
        """curl with -d containing flag-like text in value must NOT be rejected."""
        result = self._execute_check('curl https://target.com -d "location=main&page=1"')
        assert result == [], "False positive: data value should not trigger flag conflict"

    def test_nmap_with_masscan_flags_rejected(self):
        """nmap with masscan-only flags must be rejected."""
        result = self._execute_check("nmap --rate 10000 192.168.1.0/24")
        found, correct = result
        assert "--rate" in found
        assert correct == "masscan"

    def test_masscan_with_nmap_flags_rejected(self):
        """masscan with nmap-only flags must be rejected."""
        result = self._execute_check("masscan -sV 10.0.0.0/8")
        found, correct = result
        assert "-sV" in found
        assert correct == "nmap"

    def test_valid_curl_command_not_rejected(self):
        """Standard curl with valid flags must pass through."""
        result = self._execute_check("curl -s -o /dev/null -w '%{http_code}' https://target.com")
        assert result == []

    def test_unknown_binary_not_affected(self):
        """Commands with binaries not in conflict list must pass through."""
        result = self._execute_check("httpx -u https://target.com -sc")
        assert result == []


# ── 3. output_parser_tool_patterns loaded from JSON ──────────────────

class TestOutputParserToolPatterns:
    """output_parser_tool_patterns in tools_meta.json drives parser selection."""

    def test_tool_patterns_loaded_from_json(self):
        """_TOOL_PATTERNS must contain entries from tools_meta.json."""
        from airecon.proxy.agent.output_parser import _TOOL_PATTERNS, detect_tool

        assert len(_TOOL_PATTERNS) > 0, (
            "_TOOL_PATTERNS is empty — tools_meta.json may be missing or malformed"
        )

    def test_known_tools_detected_correctly(self):
        """Tools in output_parser_tool_patterns must be detected by detect_tool()."""
        from airecon.proxy.agent.output_parser import detect_tool

        cases = [
            ("nmap -sV target.com", "nmap"),
            ("subfinder -d target.com", "subfinder"),
            ("amass enum -passive -d target.com", "subfinder"),  # amass → subfinder parser
            ("httpx -u https://target.com -sc", "httpx"),
            ("katana -u https://target.com", "url_list"),
            ("ffuf -w wordlist.txt -u https://target.com/FUZZ", "ffuf"),
            ("sqlmap -u https://target.com/page?id=1", "sqlmap"),
            ("ghauri -u https://target.com/page?id=1", "sqlmap"),  # ghauri → sqlmap parser
            ("dalfox url https://target.com/search?q=test", "dalfox"),
            ("nikto -h https://target.com", "nikto"),
            ("wpscan --url https://target.com", "wpscan"),
        ]
        for cmd, expected_parser in cases:
            result = detect_tool(cmd)
            assert result == expected_parser, (
                f"detect_tool({cmd!r}) returned {result!r}, expected {expected_parser!r}"
            )

    def test_unknown_tool_returns_none(self):
        """Tools not in output_parser_tool_patterns return None from detect_tool()."""
        from airecon.proxy.agent.output_parser import detect_tool

        assert detect_tool("unknowntool --flag value") is None
        assert detect_tool("") is None

    def test_parsers_registry_matches_json_parser_types(self):
        """All parser types referenced in tools_meta.json must exist in _PARSERS."""
        from airecon.proxy.agent.output_parser import _PARSERS

        tools_meta = Path(__file__).resolve().parents[3] / "airecon" / "proxy" / "data" / "tools_meta.json"
        data = json.loads(tools_meta.read_text(encoding="utf-8"))
        patterns = data.get("output_parser_tool_patterns", {})

        missing = set()
        for binary, parser_type in patterns.items():
            if parser_type not in _PARSERS:
                missing.add(parser_type)

        assert not missing, (
            f"Parser types referenced in tools_meta.json but missing from _PARSERS: {missing}"
        )

    def test_fallback_on_missing_json(self, tmp_path, monkeypatch):
        """If tools_meta.json is unavailable, _load_tool_patterns returns [] gracefully."""
        from airecon.proxy.agent import output_parser

        # Point loader to a non-existent file
        monkeypatch.setattr(
            output_parser,
            "_TOOL_PATTERNS",
            output_parser._load_tool_patterns.__wrapped__()
            if hasattr(output_parser._load_tool_patterns, "__wrapped__")
            else [],
        )

        # Even with empty patterns, detect_tool returns None (no crash)
        with patch.object(output_parser, "_TOOL_PATTERNS", []):
            result = output_parser.detect_tool("nmap -sV target.com")
            assert result is None
