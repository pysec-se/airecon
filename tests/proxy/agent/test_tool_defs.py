"""Tests for Tool Definitions."""
from __future__ import annotations

class TestToolDefs:
    def test_tool_defs_module_imports(self):
        from airecon.proxy.agent import tool_defs
        assert tool_defs is not None

    def test_tool_definitions_exist(self):
        from airecon.proxy.agent.tool_defs import (
            get_tool_definitions,
        )
        tools = get_tool_definitions()
        assert isinstance(tools, list)
        assert len(tools) > 0
