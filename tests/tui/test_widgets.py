import pytest
from textual.app import App, ComposeResult
from airecon.tui.widgets.chat import ChatPanel
from airecon.tui.widgets.workspace import WorkspacePanel
from airecon.tui.widgets.status import StatusBar
from textual.widgets import RichLog

# A dummy Textual app to host isolated widgets
class WidgetTestApp(App):
    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat")
        yield WorkspacePanel("/tmp", id="workspace")
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
        
        # In Textual, reactive updates map to `_get_status_text` internally
        render_content = status_bar._get_status_text()
        assert "online" in render_content or "●" in render_content
        assert "offline" in render_content or "○" in render_content
        assert "5" in render_content
