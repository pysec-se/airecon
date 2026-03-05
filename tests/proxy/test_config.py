import pytest
import os
import json
from pathlib import Path
from airecon.proxy.config import Config, DEFAULT_CONFIG


def test_config_default_initialization(tmp_path):
    # Using a fake path ensures it starts from defaults
    cfg = Config.load(tmp_path / "missing_config.json")
    assert cfg.ollama_model == DEFAULT_CONFIG["ollama_model"]
    assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]


def test_config_file_loading(tmp_path):
    config_file = tmp_path / "config.json"
    custom_settings = {
        "ollama_model": "test-model:latest",
        "proxy_port": 8080,
    }
    with open(config_file, "w") as f:
        json.dump(custom_settings, f)

    cfg = Config.load(config_file)
    
    # Custom values should be present
    assert cfg.ollama_model == "test-model:latest"
    assert cfg.proxy_port == 8080
    
    # Missing values should fall back to default
    assert cfg.docker_image == DEFAULT_CONFIG["docker_image"]
    assert cfg.ollama_timeout == DEFAULT_CONFIG["ollama_timeout"]


def test_config_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRECON_PROXY_PORT", "9999")
    monkeypatch.setenv("AIRECON_OLLAMA_ENABLE_THINKING", "false")
    monkeypatch.setenv("AIRECON_COMMAND_TIMEOUT", "120.5")

    cfg = Config.load(tmp_path / "missing_config.json")

    assert cfg.proxy_port == 9999
    assert cfg.ollama_enable_thinking is False
    assert cfg.command_timeout == 120.5


def test_config_invalid_env_types_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRECON_PROXY_PORT", "not-a-number")
    
    cfg = Config.load(tmp_path / "missing_config.json")
    # Should ignore the invalid int conversion and keep default
    assert cfg.proxy_port == DEFAULT_CONFIG["proxy_port"]
