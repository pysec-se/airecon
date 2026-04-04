import json

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


class InputHistoryApp(App):
    def __init__(self, history_file, **kwargs):
        super().__init__(**kwargs)
        self.history_file = history_file

    def compose(self) -> ComposeResult:
        yield CommandInput(id="cmd", history_file=self.history_file)


@pytest.mark.asyncio
async def test_command_input_persistent_history_file_roundtrip(tmp_path):
    history_file = tmp_path / "history.log"

    async with InputHistoryApp(history_file).run_test() as pilot:
        cmd = pilot.app.query_one("#cmd", CommandInput)
        cmd.focus()

        cmd.text = "scan example.com deeply"
        await pilot.press("enter")
        await pilot.pause()

    assert history_file.exists()
    lines = history_file.read_text(encoding="utf-8").splitlines()
    assert lines
    last = json.loads(lines[-1])
    assert last["prompt"] == "scan example.com deeply"

    async with InputHistoryApp(history_file).run_test() as pilot:
        cmd = pilot.app.query_one("#cmd", CommandInput)
        cmd.focus()

        await pilot.press("up")
        await pilot.pause()

        assert cmd.text == "scan example.com deeply"


@pytest.mark.asyncio
async def test_command_input_history_down_restores_draft(tmp_path):
    history_file = tmp_path / "history.log"
    history_file.write_text(
        json.dumps({"prompt": "first history"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    async with InputHistoryApp(history_file).run_test() as pilot:
        cmd = pilot.app.query_one("#cmd", CommandInput)
        cmd.focus()

        cmd.text = "draft prompt"
        await pilot.pause()

        await pilot.press("up")
        await pilot.pause()
        assert cmd.text == "first history"

        await pilot.press("down")
        await pilot.pause()
        assert cmd.text == "draft prompt"
