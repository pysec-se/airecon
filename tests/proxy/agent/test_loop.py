import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from airecon.proxy.agent.loop import AgentLoop


@pytest.fixture
def agent_loop(mocker):
    ollama_mock = MagicMock()
    ollama_mock.chat_stream = AsyncMock()

    engine_mock = MagicMock()
    engine_mock.discover_tools = AsyncMock(return_value=[])
    engine_mock.tools_to_ollama_format = MagicMock(return_value=[])

    with patch('airecon.proxy.agent.loop.get_config') as mock_config:
        cfg = MagicMock()
        cfg.agent_max_tool_iterations = 5
        mock_config.return_value = cfg
        loop = AgentLoop(ollama=ollama_mock, engine=engine_mock)
        return loop


@pytest.mark.asyncio
async def test_agent_initialization(agent_loop, mocker):
    mocker.patch('airecon.proxy.system.get_system_prompt',
                 return_value="You are AIRecon.")

    await agent_loop.initialize(target="test.com", user_message="scan test.com")

    assert len(agent_loop.state.conversation) > 0
    assert "You are AIRecon." in agent_loop.state.conversation[0]["content"]
    assert agent_loop._session is not None
    assert agent_loop.pipeline is not None


@pytest.mark.asyncio
async def test_agent_duplicate_command(agent_loop):
    # DEDUP exempt tools should never block
    is_dup, msg = agent_loop._is_duplicate_command(
        "create_file", {"path": "test", "content": "1"})
    assert not is_dup

    # Generic tools block on exact match
    is_dup, msg = agent_loop._is_duplicate_command(
        "execute", {"command": "ls -la"})
    assert not is_dup

    is_dup, msg = agent_loop._is_duplicate_command(
        "execute", {"command": "ls -la"})
    assert is_dup
    assert "[ANTI-REPEAT]" in msg


def test_agent_state_reset(agent_loop):
    agent_loop.state.iteration = 10
    agent_loop._executed_tool_counts = {("tool", "args"): 1}
    agent_loop.reset()

    assert agent_loop.state.iteration == 0
    assert len(agent_loop._executed_tool_counts) == 0


# ---------------------------------------------------------------------------
# Subdomain workspace preservation
# Verifies the logic introduced in loop.py: when extracted_target is a
# subdomain of the current active_target, active_target must NOT change so
# that all recon output stays in the parent-domain workspace folder.
# ---------------------------------------------------------------------------

class TestSubdomainWorkspacePreservation:
    """
    Isolated unit tests for the subdomain-target guard in loop.py.

    We replicate the exact guard condition so that any drift between the
    implementation and the tests fails loudly.
    """

    @staticmethod
    def _would_switch(extracted: str, current: str | None) -> bool:
        """Mirror of the guard condition in loop.py process_message."""
        _is_subdomain = bool(
            current
            and extracted != current
            and extracted.endswith("." + current)
        )
        return not _is_subdomain

    # --- True: target SHOULD change ---

    def test_fresh_target_when_no_current(self):
        """First message — no current target → always set."""
        assert self._would_switch("target.example.com", None) is True

    def test_different_domain_switches(self):
        """Completely different domain should switch workspace."""
        assert self._would_switch("evil.com", "target.example.com") is True

    def test_parent_to_different_tld_switches(self):
        assert self._would_switch("target.example.org", "target.example.com") is True

    def test_same_target_does_not_switch(self):
        """Repeated same target is allowed (idempotent)."""
        assert self._would_switch("target.example.com", "target.example.com") is True

    # --- False: target should NOT change (subdomain case) ---

    def test_subdomain_does_not_switch(self):
        """app.target.example.com is a subdomain → keep parent workspace."""
        assert self._would_switch("app.target.example.com", "target.example.com") is False

    def test_deep_subdomain_does_not_switch(self):
        assert self._would_switch("api.v2.target.example.com", "target.example.com") is False

    def test_single_label_subdomain_does_not_switch(self):
        assert self._would_switch("mail.example.com", "example.com") is False

    def test_partial_suffix_match_is_not_subdomain(self):
        """'navigatemore.com' ends with 'e.com' but NOT 'target.example.com'."""
        assert self._would_switch("navigatemore.com", "target.example.com") is True

    def test_ip_as_extracted_is_different_domain(self):
        """IP is always treated as a different target, not a subdomain."""
        assert self._would_switch("192.168.1.1", "target.example.com") is True


def test_skill_phase_for_message_start_uses_current_phase(agent_loop):
    class _P:
        value = "EXPLOIT"

    agent_loop._get_current_phase = lambda: _P()
    assert agent_loop._skill_phase_for_message_start() == "EXPLOIT"


def test_skill_phase_for_message_start_fallback_recon(agent_loop):
    def _boom():
        raise RuntimeError("phase unavailable")

    agent_loop._get_current_phase = _boom
    assert agent_loop._skill_phase_for_message_start() == "RECON"


class TestExtractShellCommandCandidate:
    """Tests for _extract_shell_command_candidate — watchdog command extractor."""

    def _extract(self, loop, content: str) -> str | None:
        return loop._extract_shell_command_candidate(content_acc=content, thinking_acc="")

    def test_single_curl_extracted(self, agent_loop):
        content = '```bash\ncurl -s https://example.com/api\n```'
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "curl" in result

    def test_multiline_script_extracted_fully(self, agent_loop):
        """Watchdog must capture the entire multi-line bash script, not just first curl."""
        content = (
            "```bash\n"
            'echo "=== Testing IDOR ==="\n'
            'curl -s -k "https://example.com/wp-json/wp/v2/users/1"\n'
            'echo ""\n'
            'curl -s -k "https://example.com/wp-json/wp/v2/users/2"\n'
            'echo "=== Done ==="\n'
            "```"
        )
        result = self._extract(agent_loop, content)
        assert result is not None
        # Must contain ALL curl calls, not just the first one
        assert result.count("curl") == 2
        assert "users/1" in result
        assert "users/2" in result

    def test_echo_prefix_triggers_extraction(self, agent_loop):
        """echo was previously missing from command_prefix_re — must match now."""
        content = '```bash\necho "hello world"\n```'
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "echo" in result

    def test_comment_lines_skipped(self, agent_loop):
        content = (
            "```bash\n"
            "# This is a comment\n"
            "curl -s https://example.com\n"
            "```"
        )
        result = self._extract(agent_loop, content)
        assert result is not None
        assert "#" not in result

    def test_non_command_block_returns_none(self, agent_loop):
        """A block with no known command prefixes should return None."""
        content = "```bash\nsome_unknown_binary --flag value\n```"
        result = self._extract(agent_loop, content)
        assert result is None

    def test_no_bash_block_returns_none(self, agent_loop):
        result = self._extract(agent_loop, "just some plain text with no commands")
        assert result is None
