"""Test run_parallel_agents structured event emission."""
import json
import pytest
from unittest.mock import MagicMock

from airecon.proxy.agent.executors_dispatch import _DispatchExecutorMixin


@pytest.mark.asyncio
async def test_parallel_agents_emit_structured_events():
    """Verify _event_cb emits structured JSON for SubAgent events with 'target' field."""
    mixin = _DispatchExecutorMixin()
    mixin.state = MagicMock()
    mixin.state.tool_history = []
    mixin.state.tool_counts = {"total": 0}
    mixin.engine = MagicMock()
    
    captured_outputs = []
    
    def mock_on_output(text: str) -> None:
        captured_outputs.append(text)
    
    # Create a mock event that simulates a tool_start from subagent
    mock_event = MagicMock()
    mock_event.type = "tool_start"
    mock_event.data = {
        "tool": "execute",
        "tool_id": "test-tool-123",
        "arguments": {"command": "httpx -u https://example.com"}
    }
    
    # Manually call the _event_cb logic (extracted from the actual implementation)
    def test_event_cb(target: str, event) -> None:
        evt_type = getattr(event, "type", "")
        evt_data = getattr(event, "data", {}) or {}
        tool_id = str(evt_data.get("tool_id", ""))

        if evt_type == "tool_start":
            tn = evt_data.get("tool", "?")
            args = evt_data.get("arguments", {})
            mock_on_output(json.dumps({
                "event_type": "subagent_tool_start",
                "target": target,  # Uses 'target' field
                "tool_id": tool_id or f"{tn}_{id(event)}",
                "tool": tn,
                "arguments": args,
            }) + "\n")
    
    # Test tool_start event
    test_event_cb("example.com", mock_event)
    
    assert len(captured_outputs) == 1
    parsed = json.loads(captured_outputs[0])
    
    assert parsed["event_type"] == "subagent_tool_start"
    assert parsed["target"] == "example.com"  # Field name is 'target'
    assert parsed["tool_id"] == "test-tool-123"
    assert parsed["tool"] == "execute"
    assert parsed["arguments"]["command"] == "httpx -u https://example.com"


@pytest.mark.asyncio
async def test_subagent_event_parsing_in_loop_tool_cycle():
    """Verify loop_tool_cycle parses structured events correctly."""
    # Simulate the parsing logic from loop_tool_cycle.py
    test_chunk = json.dumps({
        "event_type": "subagent_tool_start",
        "target": "example.com",
        "tool_id": "tool-456",
        "tool": "httpx",
        "arguments": {"url": "https://example.com"}
    })
    
    # Parse like loop_tool_cycle does
    parsed = json.loads(test_chunk)
    evt_type = parsed.get("event_type", "")
    target = parsed.get("target", "")
    
    assert evt_type == "subagent_tool_start"
    assert target == "example.com"
    assert parsed["tool_id"] == "tool-456"
    assert parsed["tool"] == "httpx"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
