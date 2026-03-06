import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from airecon.proxy.agent.loop import AgentLoop
from airecon.proxy.agent.models import AgentState


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
