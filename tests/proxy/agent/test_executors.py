import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from airecon.proxy.agent.executors import _ExecutorMixin
from airecon.proxy.agent.models import AgentState, ToolExecution


class DummyState:
    def __init__(self):
        self.active_target = "example.com"
        self.tool_history = []
        self.tool_counts = {"exec": 0, "total": 0}


class DummyAgent(_ExecutorMixin):
    def __init__(self):
        self.state = DummyState()
        self._executed_tool_counts = {}
        self._last_output_file = None
        self._session = None

    def _normalize_args_for_dedup(self, tool_name, args):
        return tool_name, str(args)

    def _save_tool_output(self, tool_name, arguments, result):
        pass


@pytest.fixture
def agent():
    return DummyAgent()


@pytest.mark.asyncio
async def test_execute_local_browser_tool(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.browser_action',
                 return_value={"title": "Test Page"})

    success, duration, result, out_file = await agent._execute_local_browser_tool("browser_action", {"action": "goto", "url": "http://test.com"})

    assert success
    assert result["result"]["title"] == "Test Page"
    assert len(agent.state.tool_history) == 1
    assert agent.state.tool_history[0].tool_name == "browser_action"


@pytest.mark.asyncio
async def test_execute_filesystem_tool_read(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.read_file', return_value={
                 "success": True, "result": "file content"})

    success, duration, result, out_file = await agent._execute_filesystem_tool("read_file", {"path": "test.txt"})

    assert success
    assert result["result"] == "file content"
    assert "test.txt" in agent.state.tool_history[0].arguments["path"]


@pytest.mark.asyncio
async def test_execute_web_search_tool(agent, mocker):
    async def mock_search(*args, **kwargs):
        return {"success": True, "result": "Search Results String"}

    mocker.patch('airecon.proxy.agent.executors.web_search',
                 side_effect=mock_search)

    with patch('airecon.proxy.agent.executors.get_workspace_root', return_value=MagicMock()):
        with patch('builtins.open', mocker.mock_open()):
            success, duration, result, saved_path = await agent._execute_web_search_tool({"query": "test query"})

            assert success
            assert "Search Results String" in result["result"]
            assert saved_path is not None


@pytest.mark.asyncio
async def test_execute_report_tool(agent, mocker):
    mocker.patch('airecon.proxy.agent.executors.create_vulnerability_report',
                 return_value={"success": True, "finding_id": "VULN-1"})

    success, duration, result, out_file = await agent._execute_report_tool("create_vulnerability_report", {"title": "Test Vuln"})

    assert success
    assert result["finding_id"] == "VULN-1"
