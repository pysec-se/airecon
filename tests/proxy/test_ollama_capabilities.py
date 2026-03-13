from unittest.mock import patch
import ollama as _ollama

from airecon.proxy.ollama import _detect_model_capabilities_from_show, OllamaClient


def test_prefers_show_metadata_for_thinking_and_tools() -> None:
    show_data = {
        "capabilities": ["tools"],
        "template": "System prompt with <thinking> blocks",
    }
    thinking, native_tools = _detect_model_capabilities_from_show("custom:latest", show_data)
    assert thinking is True
    assert native_tools is True


def test_tools_without_thinking_are_not_enabled_for_airecon() -> None:
    show_data = {
        "capabilities": ["tools"],
        "template": "No reasoning tags",
        "modelfile": "FROM x",
    }
    thinking, native_tools = _detect_model_capabilities_from_show("custom:latest", show_data)
    assert thinking is False
    assert native_tools is False


def test_thinking_detected_from_template_think_tag() -> None:
    show_data = {"capabilities": [], "template": "...<think>...</think>..."}
    thinking, native_tools = _detect_model_capabilities_from_show("mymodel:latest", show_data)
    assert thinking is True
    assert native_tools is False  # no tools capability reported


def test_empty_show_response_returns_false_false() -> None:
    thinking, native_tools = _detect_model_capabilities_from_show("unknown:latest", {})
    assert thinking is False
    assert native_tools is False


def test_none_capabilities_field_handled_gracefully() -> None:
    show_data = {"capabilities": None, "template": "<thinking>", "modelfile": ""}
    thinking, native_tools = _detect_model_capabilities_from_show("model:tag", show_data)
    assert thinking is True
    assert native_tools is False


def test_detect_capabilities_returns_none_on_connection_error() -> None:
    """_detect_capabilities() returns None (not False) on transient Ollama error."""
    with patch("ollama.Client") as mock_client_cls:
        mock_client_cls.return_value.show.side_effect = ConnectionRefusedError("refused")
        client = OllamaClient.__new__(OllamaClient)
        client._host = "http://127.0.0.1:11434"
        client.model = "qwen3:32b"
        result = client._detect_capabilities()
        assert result is None


def test_init_keeps_config_defaults_when_detection_fails() -> None:
    """When ollama show fails, OllamaClient keeps config defaults (not forced False)."""
    with patch("ollama.Client") as mock_client_cls, \
         patch("ollama.AsyncClient"), \
         patch("airecon.proxy.ollama.get_config") as mock_cfg:
        mock_cfg.return_value.ollama_url = "http://127.0.0.1:11434"
        mock_cfg.return_value.ollama_model = "qwen3:32b"
        mock_cfg.return_value.ollama_supports_thinking = True
        mock_cfg.return_value.ollama_supports_native_tools = True
        mock_cfg.return_value.ollama_timeout = 30
        mock_client_cls.return_value.show.side_effect = ConnectionRefusedError("refused")
        client = OllamaClient()
        # Detection failed → should keep config defaults (True), not override with False
        assert client.supports_thinking is True
        assert client.supports_native_tools is True


def test_explicit_false_config_skips_detection_entirely() -> None:
    """When both config flags are False, ollama show is never called."""
    with patch("ollama.Client") as mock_client_cls, \
         patch("ollama.AsyncClient"), \
         patch("airecon.proxy.ollama.get_config") as mock_cfg:
        mock_cfg.return_value.ollama_url = "http://127.0.0.1:11434"
        mock_cfg.return_value.ollama_model = "qwen3:32b"
        mock_cfg.return_value.ollama_supports_thinking = False
        mock_cfg.return_value.ollama_supports_native_tools = False
        mock_cfg.return_value.ollama_timeout = 30
        client = OllamaClient()
        # ollama show must never be called when both flags are False
        mock_client_cls.return_value.show.assert_not_called()
        assert client.supports_thinking is False
        assert client.supports_native_tools is False


def test_native_tools_forced_off_when_thinking_disabled() -> None:
    """native_tools cannot be True when thinking is False — invariant enforced in __init__."""
    with patch("ollama.Client") as mock_client_cls, \
         patch("ollama.AsyncClient"), \
         patch("airecon.proxy.ollama.get_config") as mock_cfg:
        mock_cfg.return_value.ollama_url = "http://127.0.0.1:11434"
        mock_cfg.return_value.ollama_model = "qwen3:32b"
        mock_cfg.return_value.ollama_supports_thinking = False
        mock_cfg.return_value.ollama_supports_native_tools = True
        mock_cfg.return_value.ollama_timeout = 30
        # Detection returns tools=True but thinking=False from config → invariant enforced
        mock_client_cls.return_value.show.return_value = {
            "capabilities": ["tools"], "template": "<think>...</think>", "modelfile": "",
        }
        client = OllamaClient()
        assert client.supports_thinking is False
        assert client.supports_native_tools is False  # forced off by invariant


def test_detection_success_overrides_optimistic_config() -> None:
    """When detection succeeds with (False, False), it overrides the True config defaults."""
    show_data = {"capabilities": [], "template": "No reasoning tags", "modelfile": "FROM x"}
    with patch("ollama.Client") as mock_client_cls, \
         patch("ollama.AsyncClient"), \
         patch("airecon.proxy.ollama.get_config") as mock_cfg:
        mock_cfg.return_value.ollama_url = "http://127.0.0.1:11434"
        mock_cfg.return_value.ollama_model = "plain-model:latest"
        mock_cfg.return_value.ollama_supports_thinking = True
        mock_cfg.return_value.ollama_supports_native_tools = True
        mock_cfg.return_value.ollama_timeout = 30
        mock_client_cls.return_value.show.return_value = show_data
        client = OllamaClient()
        # Detection succeeded → must use detected values, not keep optimistic True
        assert client.supports_thinking is False
        assert client.supports_native_tools is False
