import pytest
from textual.app import App, ComposeResult

from airecon.tui.widgets.input import CommandInput


class InputTestApp(App):
    def compose(self) -> ComposeResult:
        yield CommandInput(id="cmd")


@pytest.mark.asyncio
async def test_command_input_ctrl_a_select_all_then_backspace_clears_text():
    async with InputTestApp().run_test() as pilot:
        cmd = pilot.app.query_one("#cmd", CommandInput)
        cmd.text = "this is a long prompt that user wants to clear"
        cmd.cursor_location = (0, len(cmd.text))
        cmd.focus()
        await pilot.pause()

        await pilot.press("ctrl+a")
        await pilot.press("backspace")
        await pilot.pause()

        assert cmd.text == ""
