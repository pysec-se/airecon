import pytest
from airecon.proxy.agent.models import AgentState, ToolExecution


def test_agent_state_initializes_with_defaults():
    state = AgentState()
    assert state.conversation == []
    assert state.tool_history == []
    assert state.iteration == 0
    assert state.active_target is None


def test_agent_state_add_message():
    state = AgentState()
    state.add_message("user", "Hello World")

    assert len(state.conversation) == 1
    assert state.conversation[0] == {"role": "user", "content": "Hello World"}

    state.add_message("assistant", "Hi", tool_calls=[{"name": "test_tool"}])
    assert len(state.conversation) == 2
    assert state.conversation[1]["tool_calls"] == [{"name": "test_tool"}]


def test_agent_state_approaching_limit():
    state = AgentState(max_iterations=100)
    state.iteration = 96
    assert state.is_approaching_limit() is False

    state.iteration = 97
    assert state.is_approaching_limit() is True


def test_agent_state_truncate_conversation():
    state = AgentState()
    # Add many messages to force truncation
    for i in range(100):
        state.add_message("user", f"Message {i}")

    original_len = len(state.conversation)
    # The default budget for non-system messages limits keeping everything.
    state.truncate_conversation(max_messages=50)

    # After truncation, the actual number of messages should be bounded roughly to `max_messages` + separator
    assert len(state.conversation) < original_len
    # Since all messages are short strings, they are dropped instead of compressed text,
    # but dropped message triggers the separator adding logic.
    separator_exists = any(
        "older messages compressed/removed" in str(msg.get("content")) for msg in state.conversation)
    assert separator_exists
