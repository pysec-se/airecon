import json
from pathlib import Path

import pytest
from unittest.mock import patch, MagicMock
from airecon.proxy.agent.executors import _ExecutorMixin


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


# ── schemathesis success flag fix ─────────────────────────────────────────────

def test_schemathesis_res_dict_uses_success_variable():
    """res_dict['success'] must use the computed variable, not hardcoded True."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    start = text.find("schemathesis_fuzz error:")
    block = text[text.rfind("res_dict = {", 0, start):start]
    assert '"success": success' in block


def test_schemathesis_res_dict_error_on_failure():
    """When success is False, res_dict must include an error key."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    assert 'res_dict["error"]' in text or "res_dict['error']" in text


# ── browser_action_timeout from config fix ────────────────────────────────────

def test_browser_action_timeout_reads_config():
    """browser timeout must come from get_config().browser_action_timeout."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    assert "get_config().browser_action_timeout" in text


def test_browser_action_timeout_not_hardcoded():
    """timeout=120.0 must no longer appear in _execute_local_browser_tool."""
    src = Path(__file__).parents[3] / "airecon/proxy/agent/executors.py"
    text = src.read_text()
    start = text.find("async def _execute_local_browser_tool")
    end = text.find("\n    async def ", start + 1)
    assert "timeout=120.0" not in text[start:end]


# ── tools.json browser_action auth actions fix ────────────────────────────────

def _browser_tool_fn() -> dict:
    tools_path = Path(__file__).parents[3] / "airecon/proxy/data/tools.json"
    for t in json.loads(tools_path.read_text()):
        if t.get("function", {}).get("name") == "browser_action":
            return t["function"]
    raise AssertionError("browser_action not in tools.json")


def test_browser_action_enum_has_auth_actions():
    enum_vals = _browser_tool_fn()["parameters"]["properties"]["action"]["enum"]
    for action in ("login_form", "handle_totp", "save_auth_state", "inject_cookies", "oauth_authorize"):
        assert action in enum_vals, f"browser_action enum missing: {action}"


def test_browser_action_has_auth_param_descriptions():
    props = _browser_tool_fn()["parameters"]["properties"]
    for param in ("username", "password", "totp_secret", "cookies", "oauth_url"):
        assert param in props, f"browser_action missing param description: {param}"
