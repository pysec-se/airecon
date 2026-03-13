from airecon.proxy.ollama import _detect_model_capabilities_from_show


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
