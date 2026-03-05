import pytest
import os
import json
from unittest.mock import MagicMock
from airecon.proxy.agent.workspace import _WorkspaceMixin

class DummyState:
    def __init__(self, target):
        self.active_target = target

class DummyWorkspace(_WorkspaceMixin):
    def __init__(self, target):
        self.state = DummyState(target)


@pytest.fixture
def workspace():
    return DummyWorkspace("live-target.com")


def test_extract_targets(workspace):
    text = "We found 192.168.1.1:8080 and api.subdomain.com but ignore sample.js and test.com."
    
    targets = workspace._extract_targets_from_text(text)
    
    assert "192.168.1.1:8080" in targets
    assert "api.subdomain.com" in targets
    # Should ignore file extensions that look like TLDs (e.g. .js)
    assert "sample.js" not in targets
    # Should ignore placeholder hosts
    assert "test.com" not in targets


def test_placeholder_replacement(workspace):
    args = {
        "url": "http://example.com/api",
        "nested": [{"host": "test.com"}]
    }
    
    replaced = workspace._replace_placeholder_targets(args)
    
    assert replaced["url"] == "http://live-target.com/api"
    assert replaced["nested"][0]["host"] == "live-target.com"


def test_normalize_tool_args_string_json(workspace):
    json_str = '{"url": "http://example.com"}'
    
    normalized = workspace._normalize_tool_args("browser_action", json_str)
    
    assert normalized["url"] == "http://live-target.com"


def test_save_tool_output(workspace, tmp_path, mocker):
    mocker.patch("airecon.proxy.agent.workspace.get_workspace_root", return_value=tmp_path)
    
    # Save standard output creates a .txt and .json
    result = {"success": True, "result": {"stdout": "Open ports: 80, 443"}}
    workspace._save_tool_output("nmap_scan", {"target": "x"}, result)
    
    out_dir = tmp_path / "live-target.com" / "output"
    cmd_dir = tmp_path / "live-target.com" / "command"
    
    assert out_dir.exists()
    assert cmd_dir.exists()
    
    txt_files = list(out_dir.glob("*.txt"))
    assert len(txt_files) == 1
    assert txt_files[0].read_text() == "Open ports: 80, 443"

    json_files = list(cmd_dir.glob("*.json"))
    assert len(json_files) == 1
    
    saved_data = json.loads(json_files[0].read_text())
    assert saved_data["tool"] == "nmap_scan"


def test_save_tool_output_skipped_tools(workspace, tmp_path, mocker):
    mocker.patch("airecon.proxy.agent.workspace.get_workspace_root", return_value=tmp_path)
    
    # Skip creating output txt for noisy tools, just save to command history
    result = {"success": True, "result": "Done"}
    workspace._save_tool_output("execute", {"cmd": "ls"}, result)
    
    out_dir = tmp_path / "live-target.com" / "output"
    cmd_dir = tmp_path / "live-target.com" / "command"
    
    # Out dir exists but is empty
    assert len(list(out_dir.glob("*.txt"))) == 0
    # Command log is written
    assert len(list(cmd_dir.glob("*.json"))) == 1
