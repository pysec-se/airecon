import pytest
import tempfile
from pathlib import Path
from textual.app import App, ComposeResult
from airecon.tui.widgets.chat import ChatPanel
from airecon.tui.widgets.workspace import WorkspacePanel
from airecon.tui.widgets.status import StatusBar

# A dummy Textual app to host isolated widgets

_WORKSPACE_DIR = Path(tempfile.mkdtemp(prefix="airecon_test_"))


class WidgetTestApp(App):
    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat")
        yield WorkspacePanel(_WORKSPACE_DIR, id="workspace")
        yield StatusBar(id="status")


@pytest.mark.asyncio
async def test_chat_panel_add_messages():
    async with WidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        chat.add_user_message("Test user message")
        chat.add_assistant_message("Test AI message")
        chat.add_error_message("System error")
        chat.add_system_message("System notification")

        # We verify that standard messages were mounted to the ChatPanel
        assert len(list(chat.query(".user-message"))) > 0
        assert len(list(chat.query(".assistant-message"))) > 0


@pytest.mark.asyncio
async def test_chat_panel_tool_lifecycle():
    async with WidgetTestApp().run_test() as pilot:
        chat = pilot.app.query_one("#chat", ChatPanel)

        # Start a mock tool call
        chat.add_tool_start("tool-123", "execute", {"command": "ls"})
        await pilot.pause()

        assert "tool-123" in chat._active_tools
        tool_widget = chat._active_tools["tool-123"]

        # Append output without newlines to ensure it stays in buffer
        chat.append_tool_output("tool-123", "file1.txt ")
        await pilot.pause()
        # Verify text was buffered
        assert "file1.txt" in tool_widget._live_output_buffer

        # End tool call
        chat.update_tool_end("tool-123", True, 0.5, "output content")
        await pilot.pause()

        # Ensure it was popped from active tool tracking
        assert "tool-123" not in chat._active_tools


@pytest.mark.asyncio
async def test_status_bar_updates():
    async with WidgetTestApp().run_test() as pilot:
        status_bar = pilot.app.query_one("#status", StatusBar)

        # Update metrics
        status_bar.set_status(ollama="online", docker="offline", exec_used=5)
        await pilot.pause()

        # Assert against the new separated labels
        metrics_content = str(status_bar.query_one("#status-metrics").render())
        assert "online" in metrics_content or "●" in metrics_content
        assert "offline" in metrics_content or "○" in metrics_content

        exec_content = str(status_bar.query_one("#status-caido-exec").render())
        assert "5" in exec_content


def test_status_bar_formats_million_tokens():
    status_bar = StatusBar()
    assert status_bar._format_token_count(1_250_000).endswith("M")


def test_status_bar_set_status_coerces_numeric_fields():
    status_bar = StatusBar()
    status_bar.set_status(
        tokens="1000000",
        token_limit="65536",
        exec_used="7",
        subagents="2",
        caido_findings="9",
    )

    assert status_bar.token_count == 1_000_000
    assert status_bar.token_limit == 65_536
    assert status_bar.exec_used == 7
    assert status_bar.subagents_spawned == 2
    assert status_bar.caido_findings == 9
